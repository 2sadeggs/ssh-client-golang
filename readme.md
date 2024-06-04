# SSH Client

这是一个用 Go 语言编写的简单 SSH 客户端，支持使用密码或私钥进行身份验证，并可以执行远程命令或启动交互式会话。

## 使用方法

### 使用密码进行连接

你可以使用密码进行 SSH 连接，并选择执行远程命令或启动交互式会话。

执行远程命令：

```sh
./ssh-client -user <username> -password <password> -host <hostname> -port <port> -command <command>
```

例如：

```sh
./ssh-client -user your_username -password your_password -host your_host -port 22 -command "ls -l"
```

启动交互式会话：

```sh
./ssh-client -user your_username -password your_password -host your_host -port 22
```

### 使用私钥进行连接

你可以使用私钥进行 SSH 连接，并选择执行远程命令或启动交互式会话。

执行远程命令：

```sh
./ssh-client -user <username> -key <path_to_private_key> -keypass <key_password> -host <hostname> -port <port> -command <command>
```

例如：

```sh
./ssh-client -user your_username -key /path/to/private/key -keypass your_key_password -host your_host -port 22 -command "ls -l"
```

启动交互式会话：

```sh
./ssh-client -user your_username -key /path/to/private/key -keypass your_key_password -host your_host -port 22
```

### 参数说明

- `-user`：SSH 用户名（必选）。
- `-password`：SSH 密码（可选）。
- `-key`：私钥文件路径（可选）。
- `-keypass`：私钥密码（可选）。
- `-host`：SSH 服务器地址（必选）。
- `-port`：SSH 服务器端口，默认值为 `22`（可选）。
- `-command`：要在远程主机上执行的命令。如果未提供此参数，将启动交互式会话（可选）。

## 注意事项

1. 确保你的私钥文件路径正确且权限设置为 `600`，否则 SSH 可能会拒绝使用它：

    ```sh
    chmod 600 /path/to/private/key
    ```

2. 在生产环境中，建议使用更安全的主机密钥验证方法，而不是 `ssh.InsecureIgnoreHostKey()`。你可以改用 `ssh.FixedHostKey` 来验证已知主机密钥。

3. 确保 SSH 服务器的配置允许使用你选择的身份验证方法（密码或公钥）。

## 调试

如果连接失败，可以增加更多的调试信息来帮助诊断问题。手动尝试使用 OpenSSH 客户端进行连接，并使用 `-v` 选项获取详细调试信息：

```sh
ssh -v -i /path/to/private/key username@hostname
```

这可以帮助你确定问题的具体原因。

## 许可

此项目基于 MIT 许可。详见 [LICENSE](LICENSE) 文件。
