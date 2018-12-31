---
title: OS 课程bonus的几种思路
date: 2018-12-16 10:48:05
tags: [pwn, "萌新向"]
---
最近很多人来问我，os的bonus咋做。一开始我想都没想，一看就是rop么，但是sgy问周老师说不用rop，所以又想了好几种骚操作。由于周老师说只能把思路告诉同学们，所以这里记录一下想到的思路。(这里只讨论task2，task1太简单了就略过了)
<!--- more --->
## 题目分析
题目逻辑很简单
```c
  puts("Welcome! This is an echo function.");
  memset(&s, 0, 0x200uLL);
  v1 = read(0, &s, 0x200uLL);
  printf("%p read len %lld\n", &v1, v1);
  printf(&s);
  printf("%p read len %lld\n", &v1, v1);
  return puts("goodbye!");
```
### solution1
程序没开PIE和canary，目标是跳转到指定函数，并且第一个参数为制定值。当第一个人来问的时候，想都没想，直接rop啊，第一步把puts改到memset那边，达到无限利用的效果。第二步根据上一步泄漏出的栈地址，把栈布局成`pop_rdi_gadget`->`指定值`->`target`，然后就OK了。可是呢，sgy去问周老师，周老师说这题预期解不是ROP。于是想到了第二种做法
### solution2
观察到memset这个函数，第一个参数可控，所以我们这么操作，第一步还是同上。然后观察到目标函数的参数只取一个`unsigned int`， 因此，第二步我们把payload变成`p32(学号)+填充+格式化字符串`这样。把`memset`跳到`main`函数的`strtoul`上面的`mov     rax, [rax]`，然后把`strtoul`改成目标函数。这样就OK了。这个我也感觉不是正解，太复杂了。

# 更简单的暂时想不到了