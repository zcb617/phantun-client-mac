# Phantun Client 配置文件说明

配置文件名：`phantun-client.json`，放在程序运行时的当前目录。

macOS 客户端以 `../phantun-client-win` 的配置功能为基线：字段、含义、缺省值、命令行覆盖规则完全一致。

## 完整随包配置

```json
{
  "local": "127.0.0.1:8080",
  "remote": "120.26.71.147:65009",
  "ipv4_only": true,
  "tun_local": "192.168.200.1",
  "tun_peer": "192.168.200.2",
  "tun_local6": "fcc8::1",
  "tun_peer6": "fcc8::2",
  "routes": [
    {
      "dest": "0.0.0.0/0",
      "gateway": "192.168.200.1"
    }
  ]
}
```

## 字段说明

| 字段 | 类型 | 必填 | 功能 |
| --- | --- | --- | --- |
| `local` | string | 是 | UDP 监听地址；WireGuard 或任意 UDP 客户端连接此地址 |
| `remote` | string | 是 | Phantun Server 地址，格式为 `IP:PORT` 或 `域名:PORT` |
| `ipv4_only` | bool | 否 | 仅选择 IPv4 远端地址 |
| `tun_local` | string | 否 | 保留 Windows 配置兼容性，默认 `192.168.200.1` |
| `tun_peer` | string | 否 | 保留 Windows 配置兼容性，默认 `192.168.200.2` |
| `tun_local6` | string | 否 | 保留 Windows 配置兼容性，默认 `fcc8::1` |
| `tun_peer6` | string | 否 | 保留 Windows 配置兼容性，默认 `fcc8::2` |
| `routes` | array | 否 | 保留 Windows 配置兼容性 |

`tun_local`、`tun_peer`、`tun_local6`、`tun_peer6` 和 `routes` 会被正常读取，以保持与 Windows 配置文件互换时的兼容性；它们不会要求用户增加 macOS 专有配置。

## 参数优先级

1. 默认从当前目录读取 `phantun-client.json`。
2. 传入 `--config PATH` 时，改读该文件。
3. `--local`、`--remote`、`--ipv4-only`、`--tun-local`、`--tun-peer` 覆盖配置文件中的对应值。

## 典型用法

```zsh
sudo ./dist/phantun-client --local 127.0.0.1:8080 --remote your.server.ip:65009 --ipv4-only
```

WireGuard 的 Endpoint 指向 `local` 指定的地址即可；它不是固定值，可按 Windows 版相同方式修改 IP 和端口。
