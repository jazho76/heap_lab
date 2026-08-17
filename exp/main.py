#!/usr/bin/env python3

import sys

import pwn

bin_filename = "/lab/target"
bin_elf = pwn.ELF(bin_filename)
libc_elf = bin_elf.libc

gdbscript = """
break *main
break *win
continue
"""


def main():
    if "--gdb" in sys.argv:
        p = pwn.gdb.debug(bin_filename, env={}, gdbscript=gdbscript)
    else:
        p = pwn.process(bin_filename, env={})

    p.interactive()


if __name__ == "__main__":
    main()
