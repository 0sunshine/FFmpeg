#!/usr/bin/env python3
#
# Generate an enc=v1:... line for transcode -secure_config.

import argparse
import base64
import os
import shutil
import subprocess
import sys


KEY = bytes.fromhex("7472616e73636f64652d6b65792d3031")


def pkcs7_pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def encrypt_with_cryptography(iv, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def encrypt_with_pycryptodome(iv, data):
    from Crypto.Cipher import AES

    return AES.new(KEY, AES.MODE_CBC, iv).encrypt(data)


def encrypt_with_openssl(iv, data):
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("openssl not found")

    proc = subprocess.run(
        [
            openssl,
            "enc",
            "-aes-128-cbc",
            "-K",
            KEY.hex(),
            "-iv",
            iv.hex(),
            "-nosalt",
            "-nopad",
        ],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip())
    return proc.stdout


def encrypt(iv, data):
    errors = []

    for fn in (encrypt_with_cryptography, encrypt_with_pycryptodome, encrypt_with_openssl):
        try:
            return fn(iv, data)
        except Exception as exc:
            errors.append(f"{fn.__name__}: {exc}")

    raise SystemExit(
        "No AES backend available. Install cryptography, pycryptodome, or openssl.\n"
        + "\n".join(errors)
    )


def read_args_file(path):
    src = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        result = []
        for raw in src:
            line = raw.rstrip("\r\n")
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            if stripped.startswith("arg="):
                result.append(stripped[4:])
            else:
                result.append(line)
        return result
    finally:
        if src is not sys.stdin:
            src.close()


def main():
    parser = argparse.ArgumentParser(
        description="Generate an encrypted enc= line for transcode secure config."
    )
    parser.add_argument(
        "-f",
        "--args-file",
        help="Read one argument per line. Use '-' for stdin. Lines may be raw values or arg= values.",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments to encrypt. Use -- before arguments that start with '-'.",
    )
    ns = parser.parse_args()

    if ns.args and ns.args[0] == "--":
        ns.args = ns.args[1:]

    args = read_args_file(ns.args_file) if ns.args_file else ns.args
    if not args:
        parser.error("provide arguments after -- or with --args-file")

    plain = "".join(f"arg={arg}\n" for arg in args).encode("utf-8")
    iv = os.urandom(16)
    ciphertext = encrypt(iv, pkcs7_pad(plain))
    print("enc=v1:" + base64.b64encode(iv + ciphertext).decode("ascii"))


if __name__ == "__main__":
    main()
