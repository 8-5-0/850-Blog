---
title: pwn知识点巩固（一）
date: 2018-11-20 09:42:24
tags: [pwn, ctf, "萌新向"]
---

## 前情提要
从去年(2017年)春天就开始立志学pwn，但是到现在也还是处于半吊子水平，比赛做不出来，一看wp就恍然大悟的那种。深感羞愧，所以准备近期从头梳理一遍已经学过的，巩固一下知识，为学习新知识做准备。(所有涉及到汇编的部分均采用intel语法)
<!--- more --->
## 简单认识
什么是pwn，学习pwn断断续续这么久了，我也不能给出一个比较详细的解释，只能说说以目前自己的姿势水平来解释一下我认为的pwn。我觉得pwn，除了`stack smash`之类以leak为目的的操作，最关键的就是能控制程序流的执行，简单来说就是控制`eip`、`rip`寄存器的值。为了达到控制程序运行的效果，pwn大致上可以分为三类，栈溢出，堆溢出。第一篇文章讲讲栈溢出和ROP。
## 栈溢出
众所周知，程序运行的时候会分配一个程序运行栈。程序的执行过程可看作连续的函数调用。当一个函数执行完毕时，程序要回到调用指令的下一条指令(紧接call指令)处继续执行。函数调用过程通常使用堆栈实现，每个用户态进程对应一个调用栈结构(call stack)。编译器使用堆栈传递函数参数、保存返回地址、临时保存寄存器原有值(即函数调用的上下文)以备恢复以及存储本地局部变量。

下图是32位下程序运行栈的布局

![](/img/img_pwn-0.jpg)
ROP的核心在于一条汇编指令`retn`。函数的入口点会有这样的操作

```
push ebp
mov ebp, esp
```

出口点会有这样的操作

```
leave
retn
```
等价于以下操作

```
mov esp, ebp
pop ebp
pop eip
```
用C语言来描述就是

``` 
esp = ebp
ebp = *ebp
esp += 4
eip = *esp
```
可以发现，如果我们能控制栈上的值，就可以同时改变ebp与eip的值。而栈溢出就是我们用来控制栈上的值的工具。栈溢出的出现通常是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致与其相邻的栈中的变量的值被改变。比如如下代码

```c
#include <stdio.h>
#include <string.h>
void success() { puts("You Hava already controlled it."); }
void vulnerable() {
  char s[12];
  gets(s);
  puts(s);
  return;
}
int main(int argc, char **argv) {
  vulnerable();
  return 0;
}
```
`gets()`函数没有限制读入数据的长度，而s只申请了12个字节的长度，因此当我们输入超过12个字节时，就会改变其他本来不应该改变的值。

##参考资料
* [C 语言函数调用栈 (一)](http://www.cnblogs.com/clover-toeic/p/3755401.html)
* [C 语言函数调用栈 (二)](http://www.cnblogs.com/clover-toeic/p/3756668.html)