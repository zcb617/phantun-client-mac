# Phantun macOS 客户端

这是 phantun-client-win 的 macOS 对标实现。用户可配置的字段、命令行选项、参数优先级、UDP 监听与转发、伪 TCP 会话、多连接处理、超时回收、日志和退出清理均与 Windows 版保持同一功能设计。

## 配置

默认从当前工作目录读取 phantun-client.json：

    {
      "local": "127.0.0.1:8080",
      "remote": "服务器IP:65009",
      "ipv4_only": true
    }

| 字段 | 功能 |
| --- | --- |
| local | UDP 监听地址，WireGuard 客户端连接该地址 |
| remote | Phantun 服务端地址，格式为 IP:端口 或 域名:端口 |
| ipv4_only | 只选择 IPv4 远端地址 |
| tun_local、tun_peer、tun_local6、tun_peer6、routes | 与 Windows 版保持同一配置兼容性；Windows 版不以这些字段创建虚拟网卡，Mac 版也不会把它们变成额外的用户配置功能 |

命令行参数与 Windows 版一致，命令行值覆盖配置文件：

    ./phantun-client --local 127.0.0.1:8080 --remote example.com:65009 --ipv4-only

运行时同 Windows 版一样需要管理员授权：

    sudo ./dist/phantun-client --local 127.0.0.1:8080 --remote example.com:65009 --ipv4-only

不会增加新的配置项。程序只处理配置中的服务端地址和端口；正常退出或异常结束后会清理本次运行临时使用的系统权限。

完整字段、示例与覆盖规则见 [配置说明](./config.md)。

## 构建

    zsh build.sh

该命令生成 Intel、Apple Silicon 和 Universal Binary，产物为 dist/phantun-client。构建机需要同时具备 x86_64-apple-darwin 与 aarch64-apple-darwin Rust 目标；脚本会在缺少目标时明确提示。首次运行网络转发需要管理员授权；构建、帮助信息和配置测试不会改动系统网络。
