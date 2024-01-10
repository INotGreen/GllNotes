## 1.部署 GitLab 环境在 CentOS 7 

1. **更新系统**
   在开始安装之前，建议更新您的系统以确保所有现有的软件和库都是最新的。这可以通过运行以下命令来完成：

   ```bash
   sudo yum update
   ```

2. **安装依赖**
   GitLab 有一些依赖项，需要预先安装。可以通过以下命令安装：

   ```bash
   sudo yum install -y curl policycoreutils-python openssh-server
   ```

3. **配置防火墙**
   如果您的系统正在运行防火墙，您需要允许 HTTP 和 SSH 通信。可以通过以下命令实现：

   ```bash
   sudo firewall-cmd --permanent --add-service=http
   sudo firewall-cmd --permanent --add-service=https
   sudo firewall-cmd --permanent --add-service=ssh
   sudo firewall-cmd --reload
   ```

4. **安装邮件服务器** (可选)
   如果您打算使用 GitLab 的邮件通知功能，您需要安装一个邮件服务器，如 Postfix：

   ```
   swiftCopy codesudo yum install postfix
   sudo systemctl enable postfix
   sudo systemctl start postfix
   ```

5. **添加 GitLab 仓库并安装**
   下载并安装 GitLab 社区版（CE）的仓库安装包：

   ```bash
   curl -sS https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.rpm.sh | sudo bash
   ```

   安装 GitLab CE：

   ```bash
   sudo EXTERNAL_URL="http://yourdomain.com" yum install -y gitlab-ce
   ```

   在上面的命令中，将 `yourdomain.com` 替换为您的域名或服务器的公共 IP 地址。

6. **初始化 GitLab**
   运行 GitLab 的配置脚本以自动配置和启动 GitLab：

   ```bash
   sudo gitlab-ctl reconfigure
   ```







2.如果您只想在内网中运行 GitLab，并且没有域名，那么您可以使用内网的 IP 地址作为 `EXTERNAL_URL`。在这种情况下，GitLab 将只能在您的内网中被访问，而不能从外部网络访问。

1. **找到您的内网 IP 地址**
   在服务器上，您可以使用 `ip addr` 或 `ifconfig` 命令来查找内网 IP 地址。通常，它看起来像 `192.168.x.x`、`10.x.x.x` 或者 `172.16.x.x`。

2. **使用内网 IP 地址安装 GitLab**
   用您的内网 IP 地址替换下面命令中的 `your_internal_ip`：

   ```bash
   
   sudo EXTERNAL_URL="http://your_internal_ip" yum install -y gitlab-ce
   ```

   例如，如果您的内网 IP 地址是 `192.168.1.100`，那么命令将是：

   ```bash
   
   sudo EXTERNAL_URL="http://192.168.1.100" yum install -y gitlab-ce
   ```



## 2.卸载GitLab

卸载 GitLab CE (社区版) 从 CentOS 系统中通常涉及到几个步骤。请按照以下指南操作：

1. **停止 GitLab 服务**
   首先，停止所有 GitLab 相关的服务。可以通过以下命令来完成：

   ```bash
   sudo gitlab-ctl stop
   ```

2. **卸载 GitLab 包**
   使用 YUM 包管理器卸载 GitLab CE。执行以下命令：

   ```bash
   sudo yum remove gitlab-ce
   ```

3. **移除 GitLab 配置和数据**
   卸载 GitLab 包后，您还需要手动删除其配置文件、日志和数据。这些通常位于 `/etc/gitlab`、`/var/log/gitlab` 和 `/var/opt/gitlab`。执行以下命令来移除它们：

   ```bash
   sudo rm -rf /etc/gitlab
   sudo rm -rf /var/log/gitlab
   sudo rm -rf /var/opt/gitlab
   ```

4. **可选步骤：移除依赖和用户**
   如果您不打算在该服务器上再次安装 GitLab 或其他应用程序可能不会使用这些依赖，您可以考虑移除与 GitLab 安装相关的依赖软件和创建的用户。请注意，这一步可能会影响到系统上的其他应用程序，仅在确定不会对其他服务产生影响时执行。

5. **清理残余数据**
   确保系统中没有遗留 GitLab 的数据或配置文件。可以通过搜索整个系统来完成这一步：

   ```bash
   sudo find / -name '*gitlab*'
   ```

   如果这个命令找到了任何 GitLab 相关的文件或目录，请手动检查和删除它们。



## 3.设置密码

如果在这个过程中遇到了问题，例如忘记了您设置的密码，您可以通过服务器上的 GitLab 控制台来重置 `root` 用户的密码。这可以通过运行以下命令完成：

```bash
sudo gitlab-rails console -e production
```

然后在出现的 Ruby on Rails 控制台中，执行以下命令来更改密码：

```bash
user = User.find_by(username: 'root')
user.password = 'yournewpassword'
user.password_confirmation = 'yournewpassword'
user.save!
exit
```