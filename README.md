# TLS 1.3 Protocol Simulation in MATLAB

<p align="center">
  <img src="https://img.shields.io/badge/MATLAB-R2024a-orange?style=flat-square&logo=mathworks" alt="MATLAB">
  <img src="https://img.shields.io/badge/TLS-1.3-green?style=flat-square" alt="TLS 1.3">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

<p align="center">
  <b>基于 MATLAB 的 TLS 1.3 协议握手认证模拟实现</b>
</p>

<p align="center">
  <a href="#项目简介">项目简介</a> •
  <a href="#功能特性">功能特性</a> •
  <a href="#快速开始">快速开始</a> •
  <a href="#项目结构">项目结构</a> •
  <a href="#使用说明">使用说明</a> •
  <a href="#参考资料">参考资料</a> •
  <a href="README_EN.md">English</a>
</p>

---

## 项目简介

> **课程作业**：本项目是 **电子科技大学 (UESTC)** 研究生课程《**抗干扰与安全通信**》的课程作业。

本项目使用 **MATLAB** 模拟实现 **TLS 1.3 协议**的核心握手认证流程，重点实现了 TLS 1.3 的**密钥派生链**与**双向证书认证机制**。

通过在 MATLAB 环境中构建**客户端**和**服务器**对象，并结合一系列密码学工具类，本系统成功模拟了从 **Client Hello** 消息发起到双方 **Finished** 消息交换的完整过程，最终导出可用于实际数据加密的应用层密钥。

### 亮点

- **完整的握手流程**：实现从 ClientHello 到 Finished 的完整 TLS 1.3 握手
- **Wireshark 兼容**：生成标准 PCAP 文件和 SSL Key Log，支持流量分析和解密
- **教育友好**：代码结构清晰，适合学习 TLS 1.3 协议原理

## 功能特性

| 功能模块 | 状态 | 说明 |
|:---------|:----:|:-----|
| X25519 ECDHE 密钥交换 | ✅ | 基于椭圆曲线的安全密钥协商 |
| HKDF-SHA256 密钥派生 | ✅ | 完整的密钥派生链实现 |
| AES-128-GCM 加密 | ✅ | 握手消息的加密保护 |
| 双向证书认证 (mTLS) | ✅ | 客户端和服务器双向身份验证 |
| Certificate Verify | ✅ | RSA-PSS-RSAE-SHA256 签名验证 |
| PCAP 文件导出 | ✅ | 标准格式，Wireshark 兼容 |
| SSL Key Log 生成 | ✅ | 支持 Wireshark 解密分析 |

### 实现的握手消息

```
Client                                           Server

ClientHello
  + supported_versions
  + key_share
  + supported_groups
  + signature_algorithms  -------->
                                            ServerHello
                                          + key_share
                                   + supported_versions
                          <--------  {EncryptedExtensions}
                                     {CertificateRequest}
                                            {Certificate}
                                      {CertificateVerify}
                          <--------           {Finished}
{Certificate}
{CertificateVerify}
{Finished}                -------->
                          <=======>  [Application Data]
```

## 快速开始

### 环境要求

- **MATLAB R2024a** 或更高版本（其他版本兼容性未经测试）
- **Bouncy Castle** 加密库 (`bcprov-jdk15on-1.70.jar`)

### 安装步骤

1. **克隆仓库**

   ```bash
   git clone https://github.com/yourusername/matlab-tls13.git
   cd matlab-tls13
   ```

2. **准备证书文件**

   > **注意**：项目已包含测试用的自签名证书，可直接运行。如需重新生成，可使用 OpenSSL：

   ```bash
   # 生成服务器证书和私钥
   openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
   openssl x509 -in server_cert.pem -outform DER -out config/certificates/server/server_certificate.der
   openssl pkcs8 -topk8 -inform PEM -outform DER -in server_key.pem -out config/certificates/server/server_private_key_pkcs8.der -nocrypt

   # 生成客户端证书和私钥
   openssl req -x509 -newkey rsa:2048 -keyout client_key.pem -out client_cert.pem -days 365 -nodes
   openssl x509 -in client_cert.pem -outform DER -out config/certificates/client/client_certificate.der
   openssl pkcs8 -topk8 -inform PEM -outform DER -in client_key.pem -out config/certificates/client/client_private_key_pkcs8.der -nocrypt
   ```

3. **运行模拟**

   ```matlab
   % 在 MATLAB 中执行
   cd src
   setup_environment
   main
   ```

### 查看结果

运行完成后，在 `src/output/` 目录下会生成：

| 文件 | 说明 |
|------|------|
| `tls13_handshake_simulation.pcap` | TLS 握手流量捕获文件 |
| `tls13_simulation_sslkeylog.txt` | SSL 密钥日志文件 |

## 项目结构

```
matlab-tls13/
├── src/                                # 源代码目录
│   ├── main.m                          # 主程序入口
│   ├── setup_environment.m             # 环境配置脚本
│   ├── PcapManager.m                   # PCAP 文件与 TCP 会话管理器
│   │
│   ├── output/                         # 输出文件目录
│   │   ├── tls13_handshake_simulation.pcap
│   │   └── tls13_simulation_sslkeylog.txt
│   │
│   ├── utils/                          # 工具类目录
│   │   ├── ECDHEUtils.m                # X25519 ECDHE 密钥交换
│   │   ├── HKDFUtils.m                 # HKDF-SHA256 密钥派生
│   │   ├── AES128Utils.m               # AES-128-GCM 加解密
│   │   ├── RSAUtils.m                  # RSA 密钥管理与签名
│   │   ├── PcapWriterUtils.m           # PCAP 数据包构造
│   │   └── KeyLogFileUtils.m           # SSL 密钥日志生成
│   │
│   └── protocol/                       # 协议端点实现
│       ├── TLSProtocol.m               # TLS 1.3 协议常量定义
│       ├── Client.m                    # 客户端实现
│       └── Server.m                    # 服务器实现
│
├── lib/                                # 外部依赖库
│   └── bcprov-jdk15on-1.70.jar         # Bouncy Castle 密码学库
│
├── config/                             # 配置资源目录
│   └── certificates/                   # 证书与密钥存储
│       ├── server/                     # 服务器证书与密钥
│       │   ├── server_certificate.der
│       │   └── server_private_key_pkcs8.der
│       └── client/                     # 客户端证书与密钥
│           ├── client_certificate.der
│           └── client_private_key_pkcs8.der
│
├── LICENSE                             # MIT 许可证
├── README.md                           # 项目说明（中文）
└── README_EN.md                        # 项目说明（英文）
```

## 使用说明

### Wireshark 解密配置

1. 打开 Wireshark
2. 进入 `编辑 > 首选项 > 协议 > TLS`
3. 在 `(Pre)-Master-Secret log filename` 中配置密钥日志文件路径：
   ```
   /path/to/src/output/tls13_simulation_sslkeylog.txt
   ```
4. 打开 `tls13_handshake_simulation.pcap` 文件
5. 现在可以查看解密后的 TLS 握手消息

### 自定义配置

如需修改模拟参数，可编辑以下文件：

- `src/protocol/TLSProtocol.m` - 协议常量和密码套件
- `src/main.m` - 主程序流程

## 技术实现

### 密码学算法

| 算法 | 用途 | 实现 |
|------|------|------|
| X25519 | 密钥交换 | Bouncy Castle |
| HKDF-SHA256 | 密钥派生 | Bouncy Castle |
| AES-128-GCM | 加密 | Bouncy Castle |
| RSA-PSS-RSAE-SHA256 | 签名 | Bouncy Castle |
| SHA-256 | 哈希 | Bouncy Castle |

### 密钥派生流程

```
              0
              |
              v
    PSK ->  HKDF-Extract = Early Secret
              |
              +-----> Derive-Secret(., "ext binder" | "res binder", "")
              |                     = binder_key
              v
        Derive-Secret(., "c e traffic", ClientHello)
              |                     = client_early_traffic_secret
              v
        Derive-Secret(., "e exp master", ClientHello)
              |                     = early_exporter_master_secret
              v
        Derive-Secret(., "derived", "")
              |
              v
(EC)DHE -> HKDF-Extract = Handshake Secret
              |
              +-----> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
              |                     = client_handshake_traffic_secret
              +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
              |                     = server_handshake_traffic_secret
              v
        Derive-Secret(., "derived", "")
              |
              v
    0 -> HKDF-Extract = Master Secret
              |
              +-----> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
              |                     = client_application_traffic_secret_0
              +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
                                    = server_application_traffic_secret_0
```

## 参考资料

### 协议规范

- [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

### 技术文章

- [TLS 1.3 握手流程详解 - 掘金](https://juejin.cn/post/7126911399304888357)
- [HTTPS 扩展详解 - Halfrost's Blog](https://halfrost.com/https-extensions/)
- [TLS 1.3 协议详解 - 腾讯云](https://cloud.tencent.com/developer/article/2123171)
- [TLS 1.3 协议分析 - 知乎](https://zhuanlan.zhihu.com/p/686461033)
- [TLS 1.3 协议原理 - 绿盟科技](https://blog.nsfocus.net/tls1-3protocol/)

### 开发工具

- [Bouncy Castle Crypto APIs](https://www.bouncycastle.org/)
- [Wireshark - Network Protocol Analyzer](https://www.wireshark.org/)

## 许可证

本项目采用 [MIT License](LICENSE) 开源。

## 贡献

欢迎提交 Issue 和 Pull Request！

如果你觉得这个项目对你有帮助，请给一个 Star ⭐

---

<p align="center">
  Made with ❤️ for learning TLS 1.3
</p>
