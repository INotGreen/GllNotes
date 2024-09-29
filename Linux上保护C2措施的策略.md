

## 用Ngix服务器隐蔽C2服务端的措施

只允许 IP 地址 `192.168.1.4`（ngix服务器的IP） 访问当前Linux（C2服务端）的 `80`、`8080` 和 `8880` 端口，并阻止其他 IP 地址对这些端口的访问，你可以使用以下方法：

### 1. 使用 `iptables`

`iptables` 允许你定义非常详细的规则。以下是实现只允许 IP `192.168.1.4` 访问 `80`、`8080` 和 `8880` 端口的步骤。

允许 IP `192.168.1.4` 访问指定端口

```
sudo iptables -A INPUT -p tcp -s 192.168.1.4 --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.1.4 --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.1.4 --dport 8880 -j ACCEPT
```

阻止其他 IP 访问这些端口

```
bash复制代码sudo iptables -A INPUT -p tcp --dport 80 -j DROP
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
sudo iptables -A INPUT -p tcp --dport 8880 -j DROP
```

保存 `iptables` 规则

根据你的发行版保存 `iptables` 规则：

- **Debian/Ubuntu**:

  ```
  sudo apt install iptables-persistent
  sudo netfilter-persistent save
  ```

- **CentOS/RHEL**:

  ```
  sudo service iptables save
  ```

### 2. 使用 `ufw`

如果你使用的是 `ufw`（Ubuntu 的默认防火墙工具），你可以通过以下命令来设置。

允许 IP `192.168.1.4` 访问指定端口

```
sudo ufw allow from 192.168.1.4 to any port 80
sudo ufw allow from 192.168.1.4 to any port 8080
sudo ufw allow from 192.168.1.4 to any port 8880
```

阻止其他 IP 访问这些端口

```
sudo ufw deny 80
sudo ufw deny 8080
sudo ufw deny 8880
```

启用防火墙

```
sudo ufw enable
```

### 3. 使用 `firewalld`（CentOS/RHEL）

在 CentOS 或 RHEL 系统上，你可以使用 `firewalld` 来实现这个控制。

允许 IP `192.168.1.4` 访问指定端口

```
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.4" port protocol="tcp" port="80" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.4" port protocol="tcp" port="8080" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.4" port protocol="tcp" port="8880" accept'
```

阻止其他 IP 访问这些端口

```
bash复制代码sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port protocol="tcp" port="80" drop'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port protocol="tcp" port="8080" drop'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port protocol="tcp" port="8880" drop'
```

重新加载防火墙规则

```
sudo firewall-cmd --reload
```

总结

根据你所使用的防火墙工具（`iptables`、`ufw` 或 `firewalld`），可以分别设置规则来只允许特定的 IP 访问指定的端口，并阻止其他所有 IP 的访问。