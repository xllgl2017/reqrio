# 📦 reqrio — 轻量、高性能、指纹级 HTTP 请求库

`reqrio` 是为协议研究、TLS 指纹控制、高并发采集和复杂网络环境模拟而设计的 HTTP 请求库。它不仅支持 HTTP/1.1 和 HTTP/2，而且通过
`reqtls` 提供可编排的 TLS 握手构造，帮助开发者实现浏览器级别的网络行为模拟。

不同于以“简单易用”为核心的 HTTP 客户端，`reqrio` 更强调：

- 浏览器级 TLS 指纹一致性
- 可控 Header 顺序
- HTTP/2 行为控制
- 低拷贝高并发能力
- 多语言 FFI 绑定支持

> ⚡ **适用场景**：协议研究 | 反爬绕过 | 指纹控制 | 高并发系统

---

## ✨ 核心特性

| 类别            | 能力                                 |
|---------------|------------------------------------|
| **协议支持**      | HTTP/1.1、HTTP/2                    |
| **TLS 支持**    | TLS 1.2 / TLS 1.3，浏览器级 TLS 构造      |
| **TLS 指纹**    | JA3、JA4、ClientHello、随机指纹           |
| **请求模式**      | 同步 & 异步                            |
| **请求头控制**     | 有序 Header，模拟浏览器排序                  |
| **流式传输**      | 低拷贝数据管道，支持大文件上传与流式响应               |
| **代理支持**      | HTTP 代理、SOCKS5 代理                  |
| **Cookie 管理** | 自动继承与会话维持                          |
| **压缩支持**      | Gzip、Deflate、Brotli、Zstd           |
| **多语言绑定**     | Rust、Python、Java、Node.js、Go、Qt/C++ |

---

## 🌊 低拷贝架构

`reqrio` 采用低拷贝设计，目的是在实现复杂网络行为模拟的同时，尽量降低内存开销。

- 发送阶段：form-data、JSON、文本等数据会先转为 bytes 存储。只有在 TLS 加密阶段发生一次复制，其他阶段通过借用传递。
- 文件上传：通过 `into_reader` 读取，避免一次性将全部文件加载到内存中。
- 接收阶段：TLS 解密后的数据直接写入内部 buffer，由引擎层解压解析后返回。

```text
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ Write ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
│        Form  ┌─────────┐           ┌───────────────┐           ┌─────────────┐           ┌──────┐ │
│ User ───────►│  Req    │  Body     │ RequestBuf    │  Buffer   │             │ Encrypted │      │ │
│        Json  │ Engine  ├─ Cow<T> ──┤ Header + Body │──────────►│  TlsStream  │──────────►│ TCP  │ │
│        Files │ (Sync)  │ Lifetime  │    Readers    │           │   Encrypt   │           │ Send │ │
│ User ───────►│ (Async) │           │ (borrowed)    │           │             │           │      │ │
│              └─────────┘           └───────────────┘           └─────────────┘           └──────┘ │    
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  Read ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ─ ─ ─ ─ ┐
│                 ┌──────────┐            ┌────────┐                 │
│ ┌───────┐ read  │   TLS    │ decrypt to │ ScReq  │  return         │
│ │  TCP  │──────►│ Fragment │───────────►│ AcReq  │─────────► User  │
│ └───────┘       │ Decrypt  │            │(Engine)│ Response        │
│                 └──────────┘            └────────┘                 │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘

```
---

## 🔐 TLS 与指纹

`reqrio` 的 TLS 功能由 `reqtls` 提供，`reqtls` 不是系统 TLS 封装，而是一个可编排的 TLS 握手构造器，可用于构建浏览器级别的
ClientHello 和 TLS 行为。

### 支持能力

- TLS 1.2 / TLS 1.3
- 可控的 ClientHello 构造
- JA3 / JA4 指纹
- 自定义 TLS 指纹
- 随机 TLS 指纹
- ALPN、SNI、密码套件顺序与会话恢复控制

> ⚠️ 部分高级指纹功能在当前版本中为订阅/高级功能。

### TLS 指纹示例

```rust
use reqrio::*;

let (_, fingerprint) = Fingerprint::from_builtin("chrome-152")?;
let mut req = ScReq::new().with_fingerprint(fingerprint).with_alpn(ALPN::HTTP20);
```

也可以直接从 ClientHello 负载构造自定义指纹：

```rust
use reqrio::*;

let client_hello = hex::decode("...")?;
let mut req = ScReq::new().with_fingerprint(Fingerprint::from_client_hello(client_hello, "<token>")?);
```

---

## 🚀 快速开始

### 初始化 Session

```rust
use reqrio::*;

fn main() {
    let headers = json::object! {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
        "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": r#""Windows""#
    };

    let mut req = ScReq::new()
        .with_alpn(ALPN::HTTP20)
        .with_header_json(headers).unwrap()
        .with_timeout(Timeout::new_same(3000, 3));
}
```

### GET 请求示例

```rust
use reqrio::*;

fn main() {
    let mut req = ScReq::new();
    let mut res = req.get("https://www.baidu.com", None).unwrap();
    let header = res.header();
    let body = res.decode_body().unwrap();
    let json = res.json().unwrap();
}
```

### 表单提交

```rust
use reqrio::*;

fn main() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api";
    let data = json::object! {
        "field1": "value1",
        "field2": "value2"
    };
    let resp = req.post(url, data.form()).unwrap();
}
```

### JSON 提交

```rust
use reqrio::*;

fn main() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api";
    let data = json::object! {
        "field1": "value1",
        "field2": "value2"
    };
    let resp = req.post(url, data).unwrap();
}
```

### 提交 `Serialize` 结构体

> 需要启用 `serde` 特性

```rust
use reqrio::*;
use serde::Serialize;

fn main() {
    #[derive(Serialize)]
    struct Data {
        field1: String,
        field2: bool,
    }

    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api";
    let resp = req.post(url, Body::json(&Data { field1: "value".to_string(), field2: false }).unwrap()).unwrap();
}
```

---

## 🔌 WebSocket 支持

```rust
use reqrio::*;

fn main() {
    let mut ws = WebSocket::open_sync("wss://echo.websocket.org").unwrap();
    ws.write_frame(WsFrame::new_text(true, "Hello")).unwrap();
    let frame = ws.read_frame().unwrap();
    println!("Received: {:?}", frame);
}
```

异步版本也可使用 `WebSocket::open_async(url)`。

---

## 📄 许可证

本项目采用 **Apache 2.0 License** 开源。

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request。

---

## 📬 联系方式

- **Telegram**：[https://t.me/+VVfbAeug-ohhZjU1](https://t.me/+VVfbAeug-ohhZjU1)
- **QQ**：1083315546
