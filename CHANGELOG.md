# Changelog

## [v6.0.0] - 2026-11-05

### Added
- **多源出口信誉与 BGP 情报引擎 (`egress_intel.py`，零第三方依赖)**：
  - 并发聚合 8 大独立 IP 情报家族（`ipapi.is` / `IPQuery` / `IPLocate` / `Blackbox v3` / `ip-api.com` / `IPinfo` / `MaxMind` / `FreeIPAPI`），实现数据源家族去重与对数赔率加权投票（`E = H / (H + N)`）。
  - 集成 RIPEstat、RIR RDAP 与 PeeringDB，自动识别「自报 ISP 与 PeeringDB Heavy Outbound 机房流量冲突」的**伪家宽**、IPXO / InterLIR / Heficed **商业租赁地址段**、**原生 IP vs 跨国广播 IP** 及 **RPKI ROA** 路由签名。
  - 接入 12 家实时 DoH DNSBL 黑名单（Spamhaus ZEN、Barracuda、SpamCop、DroneBL 等）与 15 份公开恶意/僵尸/代理 CIDR 网段库（后台自动预热），支持**同 `/24` C 段脏邻居计数**、**全 ASN 滥用密度评估**及 0–100 出口纯净度评分（`S ~ F` 级）。
  - 支持 `?ip=<public_ip>` URL 参数与顶部搜索栏任意公网 IP 信誉穿透检视。
- **主动 `:443` 反向穿透与 VLESS-Reality 偷证书识别**：服务端异步回探访问者出口 `:443` 端口并核对证书域名与 ASN 归属，精准识别非官方 ASN 借用 Microsoft / Apple / Yahoo / Amazon 等大厂证书的 Reality 伪装节点。
- **7 大激进底层协议栈、时序侧信道与跨系统硬件检测**：
  - `AF_PACKET` ECN 容错 BPF 过滤器 + 跨包 IPv4 `DF`/`IPID` 与 `TCP Timestamp (TSval)` 内核时钟频率 (`Hz`) 估算，抓捕 `osfuscate` 等仅篡改首个 SYN 包的无状态改包工具。
  - 6 脉冲 `8ms` 微突发时序侧信道（`muxjitter`），识别 `smux`/`yamux` 多路复用粘包合并特征。
  - WebRTC STUN UDP 候选握手耗时与 HTTP TCP 往返耗时差值比对（`udprtt`）及多递归上游 `ECS` 客户端子网审计（`ecs`）。
  - WASM 128-bit SIMD 验证与 60 组紧致浮点微基准尾延迟比（`cpubench`，捕捉云服务器 Hypervisor VM-Exit 抢占抖动）。
  - 跨系统 Canvas 字体光栅化彩边率与 Gamma 曲线（`fontrast`）、原生表单控件亚像素包围盒（`uigeom`）与 `Intl.Collator` Unicode ICU 排序规则指纹（`intlcoll`）。
  - Chrome 扩展公开资源扫描库扩容至 36 款（`extwar`）。
- **六大业务场景准入仪表盘**：融合出口信誉与当前浏览器指纹，实时评估 AI 大模型、流媒体解锁、社媒注册养号、无感验证码免盾、金融支付反欺诈与 SMTP 邮件投递通过率。

### Changed
- 全量探针规模从 **7 组 128 项** 升级至 **8 组 148 项**；跨层风控核验从 **18 项** 升级至 **24 项（20 项核心计分 + 4 项协议安全）**。

---

## [v5.0.0] - 2026-11-05

- 首个开源版本发布：基于 Python 3 标准库 + 只读 Linux `AF_PACKET` BPF 旁路抓包（`TCP SYN JA4T` + `TLS ClientHello JA4/JA3/PQ-KEM/ECH`）与 Tailwind CSS v4 + Preline UI 的 128 项全栈指纹与代理伪装自检工具。
