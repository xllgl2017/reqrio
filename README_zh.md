# 📦 reqrio

### Browser-grade TLS Fingerprinting & High Performance HTTP Client

[![Github](https://github.com/xllgl2017/reqrio/actions/workflows/main.yml/badge.svg)](https://github.com/xllgl2017/reqrio/actions/workflows/main.yml)
[![Apache](https://img.shields.io/badge/license-Apache2.0-blue.svg?logo=apache)](https://github.com/xllgl2017/reqrio/blob/main/LICENSE-APACHE)
[![Crates](https://img.shields.io/crates/v/reqrio.svg?logo=rust&label=rust)](https://crates.io/crates/reqrio)
[![PyPI](https://img.shields.io/pypi/v/reqrio.svg?logo=pypi)](https://pypi.org/project/reqrio/)
[![Npm](https://img.shields.io/npm/v/reqrio.svg?logo=npm)](https://www.npmjs.org/package/reqrio)
[![Maven](https://img.shields.io/maven-central/v/io.github.xllgl2017/reqrio?logo=apachemaven&label=maven)](https://search.maven.org/artifact/io.github.xllgl2017/reqrio)
[![Go](https://img.shields.io/crates/v/reqrio.svg?logo=go&label=go)](https://pkg.go.dev/github.com/xllgl2017/reqrio/reqrio-go)

[![Rustdocs](https://docs.rs/reqrio/badge.svg)](https://docs.rs/reqrio)
[![Javadocs](https://javadoc.io/badge/io.github.xllgl2017/reqrio/latest.svg)](https://javadoc.io/doc/io.github.xllgl2017/reqrio/latest)


---

🌐 **官方网站**: [reqrio](https://ms.xllgl.top/)

💡 **应用案例**: [TLS Forward](https://tlsfoward.com/) — 基于 reqrio 构建的高级抓包工具

## 概述

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`reqrio` 是一个面向 **协议研究、TLS 指纹控制、高并发采集、复杂网络环境模拟** 设计的
HTTP 请求库，主要用于需要精确控制网络行为的场景，
比如协议研究、指纹分析、高并发采集以及复杂反爬环境下的请求构造。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`reqrio` 提供浏览器级 TLS 指纹控制能力，包括 JA3、JA4、自定义 ClientHello 等功能。
同时支持同步与异步接口、多语言绑定、流式上传下载以及低内存占用设计。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`reqrio`是由Rust编写HTTP客户端请求库,并通过ffi绑定到多个语言。支持HTTP/1.1、HTTP/2.0，
并在启用 `quic` 特性时支持 HTTP/3 / QUIC；TLS 支持 TLS 1.2 和 TLS 1.3。

## reqrio 更关注另一类问题：

- TLS ClientHello 是否与浏览器一致
- Header 顺序是否可控
- HTTP/2 行为是否可控
- 指纹是否能够复现
- 高并发场景下内存是否足够低性能是否足够
- 是否同时支持同步和异步请求

## 🔐 TLS 栈与指纹系统

`reqrio` 的 TLS 能力由 **reqtls** 提供支持，是整个项目的核心模块。

### 🧩 `reqtls` — TLS 核心引擎

`reqtls` 负责构建与控制 TLS handshake 行为：

- TLS 1.2 / TLS 1.3 handshake 构造
- ClientHello 完全可编排生成
- cipher suites 顺序与策略控制
- TLS extensions 管理
- ALPN / SNI 控制
- Session Ticket / Resumption 支持
- JA3 / JA4 fingerprint 生成基础

> ⚠️ reqtls 并不是系统 TLS wrapper，而是可编排 TLS handshake 构造器

---

## ✅ 能力对比（HTTP 客户端库）

| 能力 / 特性           | reqrio       | reqwest      | requests (py) | uTLS (Go)  | curl-ffi (py) | blockreq |
|-----------------------|--------------|--------------|---------------|------------|---------------|----------|
| HTTP/1                | ✅           | ✅           | ✅            | ⚠️(需组合) | ✅            | ✅       |
| HTTP/2                | ✅           | ✅           | ❌            | ⚠️(需组合) | ⚠️(需构建)    | ⚠️       |
| HTTP/3 / QUIC         | ⚠️(quic特性) | ⚠️(实验性)   | ❌            | ❌         | ⚠️(需构建)    | ❌       |
| HTTPS / TLS           | ✅           | ✅           | ✅            | ✅         | ✅            | ⚠️       |
| Cookie 自动管理       | ✅           | ✅           | ✅            | ❌         | ⚠️            | ⚠️       |
| Proxy 代理支持        | ✅           | ✅           | ✅            | ⚠️(需组合) | ✅            | ⚠️       |
| IP+域名模式           | ✅           | ⚠️(需自定义) | ⚠️(需适配)    | ✅         | ✅            | ⚠️       |
| 重定向控制            | ✅           | ✅           | ✅            | ❌         | ⚠️            | ⚠️       |
| Header 自定义         | ✅           | ✅           | ✅            | ❌         | ⚠️            | ⚠️       |
| Header 顺序控制       | ✅           | ❌           | ❌            | ❌         | ⚠️            | ⚠️       |
| 连接复用 (Keep-Alive) | ✅           | ✅           | ⚠️(有限)      | ⚠️         | ⚠️            | ⚠️       |
| 流式请求 / 响应       | ✅           | ✅           | ⚠️(弱)        | ⚠️         | ⚠️            | ⚠️       |
| 超低延迟优化          | ✅           | ❌           | ❌            | ❌         | ⚠️            | ⚠️       |
| 高并发支持            | ✅           | ⚠️           | ❌            | ⚠️         | ⚠️            | ⚠️       |
| HTTP2指纹             | ✅           | ❌           | ❌            | ⚠️(有限)   | ❌            | ⚠️       |
| HTTP3指纹             | ✅           | ❌           | ❌            | ❌         | ❌            | ❌       |
| TLCP                  | ✅           | ❌           | ❌            | ❌         | ❌            | ❌       |
| TLS版本控制           | ✅           | ⚠️(min/max)  | ⚠️(需适配)    | ✅         | ⚠️            | ⚠️       |
| 会话密钥导出          | ✅           | ⚠️(需配置)   | ⚠️(需适配)    | ✅         | ⚠️(需版本)    | ❌       |
| 超时控制              | ✅           | ✅           | ✅            | ⚠️(需组合) | ✅            | ⚠️       |
| 文件上传与下载        | ✅           | ✅           | ✅            | ❌         | ✅            | ⚠️       |
| 多语言支持            | ✅           | ❌           | ❌            | ❌         | ❌            | ⚠️       |
| TLS会话恢复           | ⚠️(tls1.2)   | ⚠️           | ⚠️            | ⚠️         | ⚠️            | ⚠️       |
| mTls双向证书HTTP      | ⚠️(tls1.2)   | ✅           | ✅            | ✅         | ✅            | ⚠️       |

---

## 🔐 TLS / 指纹能力

| 能力 / 特性                      | reqrio         | reqwest        | requests (py) | uTLS (Go)            | curl-ffi (py)     | blockreq |
|----------------------------------|----------------|----------------|---------------|----------------------|-------------------|----------|
| ClientHello 完全可控             | ✅             | ❌             | ❌            | ⚠️（模板化）         | ❌                | ⚠️       |
| ClientHello 原始字节导入         | ✅             | ❌             | ❌            | ⚠️（模板）           | ❌                | ⚠️       |
| JA3 / JA4 构造（由指纹串还原）   | ✅             | ❌             | ❌            | ⚠️（模拟）           | ⚠️（依赖libcurl） | ⚠️       |
| JA3 / JA4 计算识别               | ❌             | ❌             | ❌            | ⚠️                   | ⚠️                | ⚠️       |
| Cipher Suites 顺序控制           | ✅             | ❌             | ❌            | ⚠️                   | ⚠️                | ⚠️       |
| Extension 类型 / 顺序自定义      | ✅             | ❌             | ❌            | ⚠️                   | ❌                | ⚠️       |
| TLS 1.2 / 1.3 精细控制           | ✅             | ⚠️(min/max)    | ❌            | ⚠️                   | ⚠️                | ⚠️       |
| TLS 版本选择（1.2 / 1.3 / TLCP） | ✅             | ⚠️(min/max)    | ⚠️（需适配）  | ✅                   | ⚠️                | ⚠️       |
| ALPN 控制（H1 / H2 / H3）        | ✅             | ⚠️（有限）     | ❌            | ❌                   | ⚠️                | ⚠️       |
| SNI 覆盖 / IP+域名模式           | ✅             | ⚠️（需自定义） | ⚠️（需适配）  | ✅                   | ✅                | ⚠️       |
| TLS 指纹随机化                   | ✅             | ❌             | ❌            | ❌                   | ❌                | ⚠️       |
| 自定义 TLS 指纹                  | ✅             | ❌             | ❌            | ⚠️                   | ❌                | ⚠️       |
| 浏览器级 TLS 模拟                | ✅             | ❌             | ❌            | ⚠️（Chrome profile） | ❌                | ⚠️       |
| 内置浏览器指纹库                 | ✅             | ❌             | ❌            | ⚠️（模板）           | ❌                | ❌       |
| Session Ticket 编排              | ✅             | ❌             | ❌            | ❌                   | ❌                | ⚠️       |
| HRR（HelloRetryRequest）         | ✅             | ✅             | ✅            | ✅                   | ✅                | ⚠️       |
| 证书压缩（Brotli）               | ✅             | ⚠️             | ❌            | ❌                   | ⚠️                | ❌       |
| mTLS 双向认证                    | ✅             | ✅             | ✅            | ✅                   | ✅                | ⚠️       |
| 自定义 CA / 证书校验开关         | ✅             | ✅             | ✅            | ✅                   | ✅                | ⚠️       |
| TLS 会话恢复                     | ⚠️（仅TLS1.2） | ⚠️             | ⚠️            | ⚠️                   | ⚠️                | ⚠️       |
| TLS 1.3 PSK / 0-RTT              | ❌             | ⚠️             | ❌            | ❌                   | ⚠️                | ❌       |
| 会话密钥导出（SSLKEYLOGFILE）    | ✅             | ⚠️（需配置）   | ⚠️（需适配）  | ✅                   | ⚠️（需版本）      | ❌       |
| ECH（未开放）                    | ⚠️             | ❌             | ❌            | ⚠️                   | ❌                | ❌       |
| TLCP / 国密（SM2 / SM3 / SM4）   | ✅             | ❌             | ❌            | ❌                   | ❌                | ❌       |

> 说明：内置 / VIP 指纹库（`Fingerprint::from_idx` / `from_builtin`）需要授权 token；
> `random()`、`new_custom()`、`from_ja3()`、`from_ja4()` 等自定义构造无需 token（未订阅仅打印 WARN）。
> TLS 1.3 的 PSK 恢复与 0-RTT 尚未实现（`reqtls/src/extend/pre_share_key.rs` 为注释状态），当前仅支持 TLS 1.2 的
> session_id / SessionTicket 恢复。

---

## 🧠 扩展能力（高级特性）

| 能力 / 特性                             | reqrio              | reqwest        | requests (py)    | uTLS (Go) | curl-ffi (py) | blockreq   |
|-----------------------------------------|---------------------|----------------|------------------|-----------|---------------|------------|
| 请求指纹一致性控制                      | ✅                  | ❌             | ❌               | ⚠️        | ⚠️            | ⚠️         |
| 多 TLS Profile 切换                     | ✅                  | ❌             | ❌               | ⚠️        | ⚠️            | ⚠️         |
| 浏览器行为模拟                          | ✅                  | ❌             | ❌               | ⚠️        | ⚠️            | ⚠️         |
| HTTP/2 指纹（SETTINGS / 窗口 / 优先级） | ✅                  | ❌             | ❌               | ❌        | ❌            | ⚠️         |
| HTTP/3 指纹（SETTINGS 帧）              | ✅（quic特性）      | ❌             | ❌               | ❌        | ❌            | ❌         |
| HTTP Header 伪装策略                    | ✅                  | ❌             | ❌               | ⚠️        | ⚠️            | ⚠️         |
| UA / ClientHello 联动                   | ✅                  | ❌             | ❌               | ⚠️        | ⚠️            | ⚠️         |
| 反检测策略支持                          | ✅                  | ❌             | ❌               | ⚠️        | ⚠️            | ⚠️         |
| ALPN / 协议版本切换                     | ✅                  | ⚠️（有限）     | ❌               | ❌        | ⚠️            | ⚠️         |
| SOCKS5 代理                             | ✅                  | ⚠️（需特性）   | ⚠️（需 PySocks） | ⚠️        | ✅            | ⚠️         |
| WebSocket（wss）                        | ✅                  | ✅（ws特性）   | ❌               | ⚠️        | ✅            | ⚠️       ` |`
| mTLS 双向认证                           | ✅                  | ✅             | ✅               | ✅        | ✅            | ⚠️         |
| 域名(SNI)覆盖 / IP+域名                 | ✅                  | ⚠️（需自定义） | ⚠️（需适配）     | ✅        | ✅            | ⚠️         |
| 底层 TLS Stream 接管                    | ⚠️（可取出 Stream） | ❌             | ❌               | ⚠️        | ⚠️            | ⚠️         |

> ⚠️ 部分功能是付费使用
---

### 🌊 低copy

`reqrio` 是一个 低拷贝（low-copy）请求发送引擎，用于高效地将 用户数据或文件数据 通过 TLS 加密后发送到 TCP。`reqrio`
针对用户传入form-data、json、bytes、text等数据进行转bytes储存，然后仅在进入 TLS 加密阶段时发生一次 copy， 其余阶段仅对数据进行
borrow（借用）。对文件上传则通过into_reader进行读取，减小内存开销

```text

        Form  ┌────────┐encode->bytes ┌──────────┐             ┌──────────┐
 User ───────►│        │─────────────►│          │             │          │
        Json  │ ScReq  │  into_bytes  │  Request │ copy slice  │ fragment │ write ┌───────┐
              │ AcReq  │              │  borrow  │────────────►│  TLS     │──────►│  TCP  │
       Files  │(Engine)│ into_reader  │  reader  │             │ Encrypt  │       └───────┘
 User ───────►│        │─────────────►│          │             │          │
              └────────┘              └──────────┘             └──────────┘
```

## 🧱 架构设计

reqrio 采用分层网络栈设计：

```text
┌────────────────────────────┐
│ HTTP Layer                 │
│ req / res / cookie / etc   │
└────────────┬───────────────┘
             │
┌────────────▼───────────────┐
│ Request Engine Layer       │
│ header ordering / stream   │
└────────────┬───────────────┘
             │
┌────────────▼───────────────┐
│ TLS Layer (reqtls)         │
│ handshake / cipher / ALPN  │
│ ClientHello builder        │
└────────────┬───────────────┘
             │
┌────────────▼───────────────┐
│ Transport Layer            │
│ TCP / proxy / socket       │
└────────────────────────────┘
```

## 多语言绑定

| Language | 类型 | Status | 文档                                                                                                 |
|----------|------|--------|------------------------------------------------------------------------------------------------------|
| Rust     | 原生 | ✅     | [docs.rs](https://docs.rs/reqrio/latest/reqrio/)                                                     |
| Python   | FFI  | ✅     | [pypi](https://pypi.org/project/reqrio/)                                                             |
| Java     | JNI  | ✅     | [Maven](https://javadoc.io/doc/io.github.xllgl2017/reqrio/latest/org/xllgl2017/package-summary.html) |
| Node.js  | FFI  | ✅     | [Node.js](https://www.npmjs.com/package/reqrio)                                                      |
| Go       | CGO  | ✅     |                                                                                                      |
| Qt/C++   | FFI  | ✅     |                                                                                                      |

## Roadmap

### v0.4

- [x] TLS 1.3 指纹 / ClientHello 控制
- [x] HTTP/3（需启用 `quic` 特性）
- [x] QUIC（需启用 `quic` 特性）

---

### v1.0

- [ ] API 稳定
- [ ] 文档站
- [ ] 长期支持版本

## 🚀 快速开始

## 许可证

该项目是Apache 2.0许可证下的开源项目。

## 贡献

欢迎提交问题和拉取请求。

## 联系方式

* Tg：https://t.me/+VVfbAeug-ohhZjU1
* QQ：1083315546