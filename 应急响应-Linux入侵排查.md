# Linux 入侵排查



- [Linux 入侵排查](#linux-入侵排查)
  - [1. 账号安全](#1-账号安全)
  - [2. 账号安全](#2-账号安全)
  - [3. 历史命令](#3-历史命令)
  - [4. 检查异常端口](#4-检查异常端口)
  - [5. 检查异常进程](#5-检查异常进程)
  - [6.检查开机启动项](#6检查开机启动项)
  - [7. 检查定时任务](#7-检查定时任务)
  - [8. 检查服务](#8-检查服务)
  - [9. 检查异常文件](#9-检查异常文件)
  - [10. 检查系统日志](#10-检查系统日志)
  - [11.Rootkit查杀](#11rootkit查杀)
  - [12.病毒查杀](#12病毒查杀)
  - [13.webshell查杀](#13webshell查杀)


## 1. 账号安全

基本使用：

1.用户信息文件 /etc/passwd

```
root:x:0:0:root:/root:/bin/bash
```

account:password:UID:GID:GECOS:directory:shell 

用户名：密码：用户ID：组ID：用户说明：家目录：登陆之后的 shell 

**注意**：无密码只允许本机登陆，远程不允许登陆

2、影子文件 

```
/etc/shadow
```

```
root:$6$oGs1PqhL2p3ZetrE$X7o7bzoouHQVSEmSgsYN5UD4.kMHx6qgbTqwNVC5oOAouXvcjQSt.Ft7ql1WpkopY0UV9ajBwUt1DpYxTCVvI/:16809:0:99999:7::: 
```

用户名：加密密码：密码最后一次修改日期：两次密码的修改时间间隔：密码有效期：密码修改

到期到的警告天数：密码过期之后的宽限天数：账号失效时间：保留

3、和账号有关的命令

who 查看当前登录用户（tty 本地登陆 pts 远程登录）

w 查看系统信息，想知道某一时刻用户的行为

uptime 查看登陆多久、多少用户，负载状态

## 2. 账号安全

1、查询特权用户特权用户(uid 为0)

```
[root@localhost ~]# awk -F: '$3==0{print $1}' /etc/passwd
```

 2、查询可以远程登录的帐号信息

```
[root@localhost ~]# awk '/\$1|\$6/{print $1}' /etc/shadow
```

3、除root帐号外，其他帐号是否存在sudo权限。如非管理需要，普通

帐号应删除sudo权限

```
 [root@localhost ~]# more /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)" 
```

4、禁用或删除多余及可疑的帐号

usermod -L user 禁用帐号，帐号无法登录，/etc/shadow 第二栏为 ! 开头

userdel user 删除 user 用户

userdel -r user 将删除 user 用户，并且将 /home 目录下的 user 目录一并删

除

## 3. 历史命令

1、root 用户的历史命令

```
histroy
```

进入用户目录下，导出历史命令。

```
cat .bash_history >> history.txt
```



## 4. 检查异常端口

使用 netstat 网络连接命令，分析可疑端口、IP、PID

```
netstat -antlp | more
```

查看下 pid 所对应的进程文件路径，

运行

```
 ls -l /proc/$PID/exe 
```

```
file /proc/$PID/exe（$PID 为对应的 pid 号）
```

## 5. 检查异常进程

使用 ps 命令，分析进程

```
ps aux | grep pid
```

```
ps -ef | grep pname
```



## 6.检查开机启动项

系统运行级别示意图：



****

| **运行级别** |                           含义                            |
| :----------: | :-------------------------------------------------------: |
|      0       |                           关机                            |
|      1       | 单用户模式，可以想象为windows的安全模式，主要用于系统修复 |
|      2       |              不完全的命令行模式，不含NFS服务              |
|      3       |            完全的命令行模式，就是标准字符界面             |
|      4       |                         系统保留                          |
|      5       |                         图形模式                          |
|      6       |                          重启动                           |

​                                                                     



查看运行级别命令

```shell
runlevel
```

系统默认允许级别

```shell
vi /etc/inittab
```

id=3：initdefault #系统开机后直接进入哪个运行级别

开机启动配置文件

```
/etc/rc.local
```

```
/etc/rc.d/rc[0~6].d
```

说明：当我们需要开机启动自己的脚本时，只需要将可执行脚本丢在 /etc/init.d 目录下，然后在 /etc/rc.d/rc*.d 文件中建立软链接即可。

## 7. 检查定时任务

1、利用 crontab 创建计划任务

列出某个用户cron服务的详细内容

```
crontab -l 
```

Tips：默认编写的crontab文件会保存在 (/var/spool/cron/用户名 例如:/var/spool/cron/root

删除每个用户cront任务(谨慎：删除所有的计划任务)

```
crontab -r 
```

使用编辑器编辑当前的crontab文件

```
crontab -e 
```

如：*/1 * * * * echo "hello world" >> /tmp/test.txt 每分钟写入文件

重点关注以下目录中是否存在恶意脚本

```shell
/var/spool/cron/*
/etc/crontab
/etc/cron.d/*
/etc/cron.daily/*
/etc/cron.hourly/*
/etc/cron.monthly/*
/etc/cron.weekly/
/etc/anacrontab
/var/spool/anacron/*
```



## 8. 检查服务

服务自启动

第一种修改方法：

```
chkconfig [--level 运行级别] [独立服务名] [on|off]
chkconfig –level 2345 httpd on //开启自启动
chkconfig httpd on //默认level是2345
```

第二种修改方法：

修改 /etc/re.d/rc.local 文件

加入 /etc/init.d/httpd start

第三种修改方法：

使用 ntsysv 命令管理自启动，可以管理独立服务和 xinetd 服务。

查询已安装的服务：

RPM 包安装的服务

chkconfig --list 查看服务自启动状态，可以看到所有的RPM包安装的服务

ps aux | grep crond 查看当前服务

源码包安装的服务

查看服务安装位置 ，一般是在/user/local/

```
service httpd start
```

搜索/etc/rc.d/init.d/ 查看是否存在

## 9. 检查异常文件

1、查看敏感目录，如/tmp目录下的文件，同时注意隐藏文件夹，以“..”为名的文件夹具有隐藏属性

2、得到发现WEBSHELL、远控木马的创建时间，如何找出同一时

间范围内创建的文件？

可以使用find命令来查找，如 

```
find /opt -iname "*" -atime 1 -type
```

f 找出 /opt 下一天前访问过的文件

3、针对可疑文件可以使用 stat 进行创建修改时间。

## 10. 检查系统日志





|      **日志文件**      |                             说明                             |
| :--------------------: | :----------------------------------------------------------: |
|       /var/log/        |                       日志默认存放位置                       |
| more /etc/rsyslog.conf |                      查看日志配置情况：                      |
|     /var/log/cron      |                 记录了系统定时任务相关的日志                 |
|     /var/log/cups      |                      记录打印信息的日志                      |
|     /var/log/dmesg     | 记录了系统在开机时内核自检的信息，也可以使用dmesg命令直接查  |
|    /var/log/mailog     |                         记录邮件信息                         |
|    /var/log/message    | 记录系统重要信息的日志。这个日志文件中会记录Linux系统的绝大多数重要信息，如果系统出现问题时，首先要检查的就应该是这个日志文件 |
|    /var/log/lastlog    | 记录系统中所有用户最后一次登录时间的日志，这个文件是二进制文件，不能直接vi，而要使用lastlog命令查看 |
|     /var/log/wtmp      | 永久记录所有用户的登录、注销信息，同时记录系统的启动、重启、关机事件。同样这个文件也是一个二进制文件，不能直接vi，而需要使用last命令来查看 |
|     /var/log/utmp      | 记录当前已经登录的用户信息，这个文件会随着用户的登录和注销不断变化，只记录当前登录用户的信息。同样这个文件不能直接vi，而要使用w,who,users等命令来查询 |
|    /var/log/secure     | 记录验证和授权方面的信息，只要涉及账号和密码的程序都会记录，比如SSH登录，su切换用户，sudo授权，甚至添加用户和修改用户密码都会记录在这个日志文件中 |
|     /var/log/btmp      | 记录错误登录日志，这个文件是二进制文件，不能直接vi查看，而要使用lastb命令查看 |





记录验证和授权方面的信息，只要涉及账号和密码的程序都会记录，比如SSH登录，su切换用户，sudo授权，甚至添加用户和修改用户密

码都会记录在这个日志文件中日志分析常用命令：

1、定位有多少IP在爆破主机的root帐号：

```
grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort | uniq -c| sort -nr | more
```

定位有哪些IP在爆破：

```
grep "Failed password" /var/log/secure|grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0- 9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][09]?)"|uniq -c
```

爆破用户名字典是什么？

```
grep "Failed password" /var/log/secure|perl -e 'while($_=<>){ /for(.*?) from/;print "$1\n";}'|uniq -c|sort -nr
```

2、登录成功的IP有哪些：

```
grep "Accepted " /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
```

登录成功的日期、用户名、IP：

```
grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'
```

3、增加一个用户kali日志：

Jul 10 00:12:15 localhost useradd[2382]: new group: name=kali,GID=1001Jul 10 00:12:15 localhost useradd[2382]: new user: name=kali,UID=1001, GID=1001, home=/home/kali, shell=/bin/bashJul 10 00:12:58 localhost passwd: pam_unix(passwd:chauthtok):password changed for kali

#grep " useradd" /var/log/secure

4、删除用户kali日志：

```
Jul 10 00:14:17 localhost userdel[2393]: delete user 'kali'

Jul 10 00:14:17 localhost userdel[2393]: removed group 'kali'
```

```
owned by 'kali'

Jul 10 00:14:17 localhost userdel[2393]: removed shadow group

'kali' owned by 'kali'

# grep " userdel" /var/log/secure
```

5、su切换用户：

```
Jul 10 00:38:13 localhost su: pam_unix(su-l:session): session

opened for user good by root(uid=0)
```

sudo授权执行:

```
sudo -l

Jul 10 00:43:09 localhost sudo: good : TTY=pts/4 ;

PWD=/home/good ; USER=root ; COMMAND=/sbin/shutdown -r
```



## 11.Rootkit查杀

Chkrootkit

网址：http://www.chkrootkit.org

Rkhunter

网址：http://rkhunter.sourceforge.net

## 12.病毒查杀

Clamav

网址：http://www.clamav.net/download.html

## 13.webshell查杀

Linux 版：河马 WebShell 查杀：http://www.shellpub.com