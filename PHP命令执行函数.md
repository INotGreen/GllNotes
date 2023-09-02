



#   PHP环境下绕过360进程链拦截，上线CobaltStrike/C2





1. **`exec`**: 执行一个外部程序，并且可以获取其输出。返回最后一行的输出。

   ```php
   exec('start notepad.exe');
   ```

2. **`shell_exec`**: 通过shell环境执行命令，并返回输出作为字符串。

   ```php
   $output = shell_exec('start notepad.exe');
   
   
   function launchNotepad() {
       if (substr(PHP_OS, 0, 3) == 'WIN') {
           shell_exec('start notepad.exe');
       }
   }
   ```

3. **`system`**: 执行外部程序，并显示原始输出。这个函数可以用来获取并直接打印外部命令的输出。

   ```php
   system('start notepad.exe');
   ```

4. **`passthru`**: 类似于`system`，但它不只是显示原始输出，还可以将原始二进制数据直接传递给浏览器。

   ```php
   passthru('start notepad.exe');
   ```

5. **`popen`** 和 **`pclose`**: 这两个函数允许你打开一个进程文件指针，并可以用来读取或写入。

   ```php
   $handle = popen('start notepad.exe', 'r');
   pclose($handle);
   ```

```php
function launchNotepad() {
    if (substr(PHP_OS, 0, 3) == 'WIN') {
        pclose(popen("start /B notepad.exe", "r"));  
    }
}
```



6**`proc_open`**: 这是一个非常强大和灵活的函数，允许你在一个新的进程中执行一个命令，并可以与该进程通过数组的文件指针进行交互。

```php
phpCopy code$descriptorspec = array(
   0 => array("pipe", "r"),  // 标准输入，子进程从此管道中读取
   1 => array("pipe", "w"),  // 标准输出，子进程向此管道中写入
   2 => array("file", "error-output.txt", "a") // 标准错误是一个文件
);

$process = proc_open('notepad.exe', $descriptorspec, $pipes);

if (is_resource($process)) {
    fclose($pipes[0]); // 关闭子进程的标准输入
    fclose($pipes[1]); // 关闭子进程的标准输出
    proc_close($process); // 关闭进程
}
```

7.**使用`COM`对象（仅限Windows）**: 如果你正在运行的是Windows服务器，并且PHP已启用COM扩展，你可以使用COM对象来调用Windows的Shell来执行命令。

```php
$WshShell = new COM("WScript.Shell");
$WshShell->Run("notepad.exe");
```

8.**使用`backticks`操作符**: 这是一个非常简洁的语法，允许你执行命令并将输出作为字符串捕获。

```
$output = `start notepad.exe`;
```

这些方法和函数都可以用来执行外部命令，但它们在功能和灵活性方面存在差异。选择哪一个取决于你的具体需求和服务器的配置。不过，同样要提醒，执行外部命令可能存在安全风险，所以应该非常小心，并确保执行的命令来自可信的源。



```php
phpCopy code$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
);

$process = proc_open('notepad.exe', $descriptorspec, $pipes);

if (is_resource($process)) {
    stream_set_blocking($pipes[1], 0); // 设置非阻塞模式
}
```

这里，`stream_set_blocking`函数设置了输出管道为非阻塞模式，这意味着PHP脚本不会等待命令完成。

9.**使用`shell_exec`或`exec`并重定向输出**:

```
shell_exec("notepad.exe > NUL 2>&1 &");
```

在这个示例中，`> NUL 2>&1 &`将命令的输出重定向到`NUL`，并让命令在后台运行。

