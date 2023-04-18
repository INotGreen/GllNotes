







# 1.mingw反汇编反调试参数说明



**在编译 C 或 C++ 程序时，可以通过加入一些特定的参数来增加程序的安全性，使得它更难被反汇编和反调试。**

64位mingw下载地址：https://github.com/niXman/mingw-builds-binaries/releases/download/12.2.0-rt_v10-rev2/x86_64-12.2.0-release-posix-seh-msvcrt-rt_v10-rev2.7z

32位mingw下载地址：https://master.dl.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/6.4.0/threads-win32/sjlj/i686-6.4.0-release-win32-sjlj-rt_v5-rev0.7z?viasf=1



**以下是一些常用的参数：**

```
1.-s
```

 参数用于指定编译器在编译过程中生成的汇编代码文件不生成符号表。在编译过程中，编译器会生成汇编代码文件（通常是以 .s 作扩展名），该文件包含了程序的汇编代码表示。汇编代码文件中的每个符号都有一个关联的符号表，该符号表包含了与该符号关联的地址、类型等信息。如果在 gcc 命令中加上 -s 参数，则编译器将不会生成符号表，这将导致生成的汇编代码文件不包含任何符号信息，从而使得该文件更难以调试和反汇编

```
2.-march=native
```

这个参数可以让编译器针对本地 CPU 进行优化，从而增加程序的性能，同时也会增加程序被反汇编的难度。

```
3.-fno-diagnostics-show-caret
```

这个参数可以让编译器在输出错误信息时不显示指向错误的箭头，从而减少程序被反汇编的可能性。

```
4.-fdata-sections -ffunction-sections -Wl,--gc-sections
```

这三个参数可以让编译器在链接时将可执行文件中的数据和函数放在不同的 section 中，并在链接时去掉未被引用的 section，从而减少程序被反汇编的可能性。

```
5.-fPIC -shared
```

这两个参数可以让编译器生成位置无关的代码和可共享的库文件，从而增加程序被反汇编和反调试的难度。

```
6.-Wl,-z,now,-z,relro,-z,noexecstack
```

这个参数可以让链接器在链接时将可执行文件中的符号表和重定位表只读化，并禁止程序在堆栈上执行代码，从而增加程序被反调试的难度

```shell
7.-fvisibility=hidden
```

这个参数可以让编译器在编译时隐藏符号信息，从而减少程序被反汇编的可能性。



```shell
8.-fPIE -pie
```

这两个参数可以让可执行文件在加载时进行地址随机化，从而增加程序被反汇编和反调试的难度。

```shell
9.-Wl,-z,noexecstack
```

这个参数可以让链接器在链接时禁止程序在堆栈上执行代码，从而防止缓冲区溢出攻击。

```shell
10.-Wl,-z,relro,-z,now
```

这个参数可以让链接器在链接时将可执行文件中的符号表和重定位表只读化，并在加载时立即进行符号解析，从而增加反调试的难度。

```shell
11.-fstack-protector-strong -D_FORTIFY_SOURCE=2
```

这两个参数可以让编译器在编译时加入一些额外的保护机制，从而防止缓冲区溢出攻击和格式化字符串攻击。

```shell
12.-O3
```

这个参数可以让编译器对代码进行更加优化，使得生成的代码更加难以理解。同时，它还会去除一些不必要的信息，从而增加反汇编的难度。

```shell
13.-fomit-frame-pointer
```

这个参数可以让编译器在生成汇编代码时去掉函数调用的栈帧指针，从而增加反汇编的难度。

```shell
14.-fno-inline
```

这个参数可以让编译器在编译时不进行函数内联，从而使得程序更难被反汇编和反调试。

```shell
15.-fstack-protector-strong
```

这个参数可以让编译器在编译时加入一些额外的保护机制，从而防止缓冲区溢出攻击。

```shell
16.-Wl,-z,now,-z,relro
```

这个参数可以让链接器在链接时将可执行文件中的符号表和重定位表只读化，并在加载时立即进行符号解析，从而增加反调试的难度。



```
17.-fstack-protector-all
```

这个参数可以让编译器在编译时为所有函数加入堆栈保护机制，从而防止缓冲区溢出攻击。

```
18.-fno-unwind-tables -fno-asynchronous-unwind-tables
```

这两个参数可以让编译器不生成用于异常处理的表格，从而减少程序被反汇编的可能性。

```
19.-Wl,-z,relro,-z,now,-z,noexecstack
```

这个参数可以让链接器在链接时将可执行文件中的符号表和重定位表只读化，并禁止程序在堆栈上执行代码，从而增加程序被反调试的难度。

```
20.-Wl,-z,defs
```

这个参数可以让链接器在链接时检查未定义的符号，并输出警告信息，从而减少程序被反汇编的可能性。

```
21.-fvisibility-inlines-hidden
```

这个参数可以让编译器在编译时将内联函数的符号信息隐藏起来，从而增加程序被反汇编的难度。

# 2.参数示例

```shell
x86_64-w64-mingw32-gcc stub.c -s -O3 -fomit-frame-pointer -fno-inline -fstack-protector-strong -mwindows -fPIE -pie -fvisibility=hidden
```

