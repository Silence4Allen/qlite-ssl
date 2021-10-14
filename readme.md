* [概述](#概述)
* [前言](#前言)
* [1、下载qlite-ssl:](#1下载qlite-ssl)
* [2、执行脚本install.sh](#2执行脚本installsh)
* [3、选择并执行对应服务](#3选择并执行对应服务)
   * [3.1、安装](#31安装)
      * [3.1.1、一键HTTPS](#311一键https)
      * [3.1.2、自定义安装证书](#312自定义安装证书)
         * [3.1.2.1、选择已安装的web服务](#3121选择已安装的web服务)
   * [3.2、更新](#32更新)
   * [3.3、卸载](#33卸载)
* [4、查看log](#4查看log)

# 概述
qlite-ssl 利用 [acme.sh](https://github.com/acmesh-official/acme.sh) 和 [letsencrypt](https://letsencrypt.org/) 生成免费的证书。

您可以根据您的主机服务器配置选择自定义安装证书，以便实现HTTPS

也可以直接选择一键HTTPS功能

证书的有效期是三个月，支持自动更新，也可以强制更新

# 前言
1、您的域名需要添加两条解析记录:

  a. 主机记录为 *@* 、记录类型为 *A* 、记录值为 *您的IP*;

  b. 主机记录为 *www* 、记录类型为 *A* 、记录值为 *您的IP*

2、您的域名若是解析到大陆的服务器，需要先进行 **备案**，否则域名访问会受到阻截

# 1、下载qlite-ssl:

使用git命令下载

```bash
git clone https://gitee.com/silence4allen/qlite-ssl.git
```

# 2、执行脚本install.sh

为避免权限问题影响获取证书流程，强烈建议使用root用户

```bash
cd qlite-ssl
sudo su
./install.sh --domain=your_domain --email=your_email --cert-path=save_your_cert_path
```

> --domain: 必需，正确解析到您当前主机的域名
>
> --email: 必需，用于注册证书时的邮箱
>
> --cert-path: 选填，用于另存您的证书，请输入**绝对路径**

# 3、选择并执行对应服务

## 3.1、安装

### 3.1.1、一键HTTPS

一键HTTPS将自动为您配置nginx作为您的默认web服务器，您无需其他任何操作。

**如果您已安装nginx作为您的web服务器，请先卸载后再使用该功能**

**注意不要占用80以及443端口**

### 3.1.2、自定义安装证书

您可以根据您的主机服务器选择对应的web服务器来获取证书，以便实现HTTPS

#### 3.1.2.1、选择已安装的web服务

*nginx: 需要配置 server_name 为您的域名以及其他必要配置文件，并且保证可访问*

*apache: 需要配置 server_name 为您的域名以及其他必要配置文件，并且保证可访问*

*other: 如果您安装的是其他web服务器，请选择other，请勿占用80以及443端口*

## 3.2、更新

强制更新您的证书

## 3.3、卸载

卸载qlite-ssl脚本服务以及acme脚本服务

# 4、查看log

你可以通过~/.qlite-ssl/log/install.log文件查看更多详细log
