#!/usr/bin/env python3
import sys
import argparse
import binascii
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def generate_random_hex(length_bytes):
    return binascii.hexlify(os.urandom(length_bytes)).decode()

def encrypt_payload(input_path, output_path, xor_key=None, aes_key_hex=None, aes_iv_hex=None):
    try:
        with open(input_path, 'rb') as f:
            data = bytearray(f.read())
        
        print(f"[*] Loaded {len(data)} bytes from {input_path}")

        # 1. XOR Encryption (First step in encryption, will be last in decryption)
        if xor_key is not None:
            print(f"[+] XOR Key: {hex(xor_key)}")
            for i in range(len(data)):
                data[i] ^= xor_key

        # 2. AES-256-CBC Encryption
        if aes_key_hex and aes_iv_hex:
            print(f"[+] AES Key: {aes_key_hex}")
            print(f"[+] AES IV:  {aes_iv_hex}")
            
            aes_key = bytes.fromhex(aes_key_hex)
            aes_iv = bytes.fromhex(aes_iv_hex)
            
            if len(aes_key) != 32:
                print("[!] AES key must be exactly 32 bytes (64 hex characters) for AES-256")
                sys.exit(1)
            if len(aes_iv) != 16:
                print("[!] AES IV must be exactly 16 bytes (32 hex characters)")
                sys.exit(1)
                
            cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            padded_data = pad(bytes(data), AES.block_size)
            data = bytearray(cipher.encrypt(padded_data))

        with open(output_path, 'wb') as f:
            f.write(data)
            
        print(f"[+] Successfully encrypted -> {output_path}")

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Payload Encryptor (XOR + AES-256-CBC)")
    parser.add_argument("input_file", help="File to encrypt")
    parser.add_argument("output_file", help="Encrypted output file")
    
    # We use a custom action or just check the presence
    parser.add_argument("--xor", action='store_true', help="Enable XOR encryption")
    parser.add_argument("--xor-key", type=lambda x: int(x, 0), help="XOR key byte (e.g., 0xAD). Generates random if omitted but --xor is set.")
    
    parser.add_argument("--aes", action='store_true', help="Enable AES-256-CBC encryption")
    parser.add_argument("--aes-key", type=str, help="AES-256 key in hex (64 chars). Generates random if omitted but --aes is set.")
    parser.add_argument("--aes-iv", type=str, help="AES IV in hex (32 chars). Generates random if omitted but --aes is set.")
                        
    args = parser.parse_args()
    
    xor_key = None
    if args.xor:
        if args.xor_key is not None:
            xor_key = args.xor_key & 0xFF
        else:
            xor_key = os.urandom(1)[0]
            
    aes_key = None
    aes_iv = None
    if args.aes:
        if args.aes_key:
            aes_key = args.aes_key
        else:
            aes_key = generate_random_hex(32)
            
        if args.aes_iv:
            aes_iv = args.aes_iv
        else:
            aes_iv = generate_random_hex(16)
            
    if not args.xor and not args.aes:
        parser.error("You must specify at least --xor or --aes")

    encrypt_payload(args.input_file, args.output_file, xor_key, aes_key, aes_iv)
