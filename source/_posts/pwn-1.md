---
title: pwn知识点巩固（二）
date: 2018-11-22 09:40:58
tags:
---
上一篇文章简单讲了讲栈溢出，这篇文章准备谈一谈ROP，顺带记录一下基础的ROP姿势。
<!--- more --->
ROP全称Return Oriented Programming， 其主要思想是在栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程。所谓 gadgets 就是以 ret 结尾的指令序列，通过这些指令序列，我们可以修改某些地址的内容，方便控制程序的执行流程。

最简单的ROP可以说是ret2text， 直接跳转到程序中已经存在并且能够满足我们需求的程序片段中，从而实现我们的目的。
如果程序中不存在我们需要的程序，并且我们能控制某一块可执行的区域，那么我们可以考虑ret2shellcode，随着ctf难度越来越高，这一种ROP方式的难度主要体现在shellcode的编写上。这里推荐一个网站
* [shellstorm](http://shell-storm.org/shellcode/)
这个网站汇集了很多很巧妙的shellcode，长度都是尽可能地短的。

当上述两种情形都不满足时，可以考虑到ret2syscall。这里的难度主要是syscall有可能被seccomp限制从而无法使用。这里也推荐两个网站，分别记录了32位和64位syscall调用的条件，
* [32](https://syscalls32.paolostivanin.com/)
* [64](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)

如果我们能知道libc的基地址，同时知道libc的版本，我们可以使用ret2libc的方法来getshell。

# 未完待续。。。