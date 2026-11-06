# Changelog

## [v7.2.6] - 2026-11-06

### Added
- **底部开源仓库跳转链接 (`static/index.html`)**：在页脚新增带 GitHub 图标与 `referrerpolicy="no-referrer"` 隐私保护属性的开源仓库超链接（`https://github.com/zzusec/whoprobe`）。

---

## [v7.2.5] - 2026-11-06

### Fixed
- **消除原生 4G/5G 蜂窝空口调度下的「Mux 粘包合并」误报 (`isMuxTunnelSuspect`)**：
  - 将微脉冲间隔由 `8ms` 拓宽至 `14ms`（避开移动端 60Hz 定时器聚合与 5G TDD 单时隙窗口），并引入三维物理握手测距与被动协议栈交叉验真：当服务端网卡 `SYN→ClientHello` 物理握手耗时与浏览器热连接 RTT 吻合（`<35ms`）、端侧原生 TCP 栈一致且出口非机房/代理网段时，准确识别为无线空口时隙攒包与 HTTP/2 单连接按序重组，不再误判为 `smux / yamux` 代理多路复用。

---

## [v7.2.4] - 2026-11-05

### Fixed
- **彻底修复真机 iPhone + 原生 5G 在 Safari/WebKit 下的残余扣分误判**：
  - **Safari / WebKit 方括号 IPv6 `RTCIceCandidate.address` 规范化 (`cleanIp` + `egress_intel.normalize_public_ip`)**：iOS Safari WebKit 返回的公网 IPv6 候选地址带外层方括号（如 `[240e:...]`），此前会导致前后端 `ip-meta` 归属匹配、前缀展开与同运营商判定失配而误报高危 `WebRTC 泄漏`；现统一剥离方括号与 `%zone` 并过滤 RFC 6598 CGNAT (`100.64.0.0/10`)、464XLAT CLAT (`192.0.0.0/24`) 等非全球单播本地接口地址。
  - **消除并发回填污染 `本站` 出口的竞态 (`probeServer` + `backfillExitMeta`)**：修复第三方边缘探针在主服务端探针尚未返回前抢写 `ex_self` / `R.ipCC` 的竞态问题，并在主探针到达后立即重算 WebRTC 与分流徽章。
  - **补齐 Apple iCloud 隐私中继 IPv6 段 (`2a09:bac2::/32`、`2a09:bac3::/32`、`2606:54c3::/32`) 与 Safari 子请求中继去误报 (`isAppleRelay` + `analyzeExitSplit`)**：当 Apple 端侧直连原生宽带/蜂窝网络（`warp=off` 且主出口非中继），仅个别跨域子探针被 Safari 内置防追踪中继接管时，不再误判为跨国代理分流（真实 VPN 规则漏底与开启 WARP 分流仍正常检出）。
  - **校准 STUN `srflx` 计时与 Anycast 就近测距守卫 (`probeWebrtc` + `rtt`)**：仅对真实 `srflx/prflx/relay` 反射候选统计 STUN 往返耗时，且在本机 TCP 握手往返吻合无泄漏时不因 STUN Anycast 节点物理更近而误报 UDP 旁路。

---

## [v7.2.3] - 2026-11-05

### Fixed
- **STUN 候选国家归因读取统一 (`candidateCC`)**：统一从 `R.ipMeta` 与并发分流矩阵 `R.exits` 读取异网候选 IP 的国家代码，确保网页直连 + UDP 走代理的反向分流场景稳定输出 `网页 CN ≠ STUN US`。

---

## [v7.2.2] - 2026-11-05

### Fixed
- **主连接出口回写竞态修复 (`probeServer` / `probeQuicAndExits`)**：当外部边缘探针先于主站 `/api/who/me` 返回并临时回填 `ex_self` 时，主站响应到达后强制以权威服务端出口覆盖 `R.exits.ex_self`，避免分流规则模式下「本站」出口国家显示错位。
- **反向规则分流（网页直连 + UDP/部分域名走代理）可读性增强 (`webrtc` / `split`)**：当主页面直连而 STUN 或部分海外域名命中代理时，冲突徽章直观展示 `网页 CN ≠ STUN US` 与 `直连 CN ≠ 代理 US`，明确区分「海外代理漏真实 IP」与「分流规则未覆盖当前域名」。
- **iOS / iPadOS 原生协议栈名称对齐 (`renderPortrait`)**：在拓扑链路与传输层磁贴中根据端侧 Apple 子平台准确显示 `iOS 栈吻合` / `iPadOS 栈吻合`，不再统一显示为 `macOS`。

---

## [v7.2.1] - 2026-11-05

### Fixed
- **消除 iOS / Safari 与原生 4G/5G 双栈蜂窝网络下的 4 项误判**：
  - **WebRTC 双栈与 5G CGNAT 同源核验 (`/api/who/ip-meta` + `isSameCarrierCandidate`)**：新增服务端轻量并发候选 IP 归属与运营商核验接口及运营商前缀归一算法；当 STUN 反射出的原生 IPv6 或异 `/16` CGNAT 公网 IP 与当前非机房出口同属一个国家与同一运营商时，准确判定为正常原生双栈/CGNAT 选路而非代理泄漏（跨国及机房/云代理泄漏仍 100% 拦截）。
  - **多出口分流双栈与同运营商地址池去误报 (`analyzeExitSplit`)**：分离 IPv4 与 IPv6 前缀统计，同国同运营商下的 IPv4/IPv6 Happy Eyeballs 双栈并发或 5G CGNAT 多地址池不再误判为多路代理分流。
  - **蜂窝移动 5GC / GTP / CLAT 原生承载 `MTU 1360–1476` 识别 (`infer_mobile` + `isCellularNativeLink`)**：补齐 `5GC` 等移动核心网自治系统识别；在原生端侧 TCP 协议栈吻合且非机房/中继出口的移动蜂窝链路上，`MTU 1420` 等承载封装不再误报为 VPN 隧道。
  - **Safari / WebKit `1ms` 隐私时钟量化下的 CPU 抢占比校准 (`cpubench`)**：新增自适应时间片标定与粗化时钟保护守卫，彻底消除 WebKit `1.0ms` 量化步长除以 `0.005ms` 下限导致的 `200x` 虚假抢占告警。
- **并发加速受限网络备援探针与可信 Cloudflare 源头校验**：国内外备援 GeoIP 探针改为并发竞速收敛，并在服务端校验官方 Cloudflare 边缘网段后安全提取 `CF-Connecting-IP`。

---

## [v7.2.0] - 2026-11-05

### Added
- **Speedtest 风格隐私脱敏分享链接与动态矢量结果徽章 (`share_store.py`)**：
  - **一键生成公开分享短链 (`/r/<id>`)**：在 148 项探针汇总确认后，顶栏与圆环总分旁展示「生成分享链接」按钮，弹窗实时预览分享卡片，支持一键复制分享短链、论坛/GitHub Markdown 签名徽章代码（`[![WhoProbe](.../r/<id>.svg)](.../r/<id>)`）及下载矢量卡片。
  - **客户端 + 服务端双重零 IP 脱敏保障**：白名单结构化提炼 + 服务端 `ipaddress` 标准库双向过滤，强制剥离全部真实公网 IPv4/IPv6（含 RFC 4291 `::` 压缩格式）、CIDR、国内分流宽带与精确城市、MAC 地址、PTR 反向主机名、经纬度及固定设备指纹哈希（`fpId` / `hwId` / `ETag`），且服务端不持久化创建者 Socket IP。
  - **免重跑瞬时快照视图与动态 OpenGraph / SVG 卡片 (`/r/<id>.svg`)**：访问 `/r/<id>` 直接水合渲染完整图形化诊断台、三节点拓扑、六大业务场景通过率与 24 项体检结论（内置 `<base href>` 自动兼容独立根域名与 `/who/` 子路径部署）；`/r/<id>.svg` 实时输出 `760×380` 暗色仪器风矢量卡片。

---

## [v7.1.1] - 2026-11-05

### Fixed
- **消除加载期间「先显示 100 分再逐步扣减」的过早计分抖动**：
  - 总分圆环仪表（`#scoreNum` / `#gradeBadge` / `#scoreRingArc`）、三色破绽计数、20 段光谱条与头号穿帮清单现严格门控于全量 148 项探针汇总确认后（`R.finished === true`）一次性加载；扫描期间保持中性「`--` / 待确认」占位并实时展示已采集探针进度。
  - 同步收紧六大业务场景通过率（`renderScenarios`）、顶栏总断胶囊（`#wowAlert`）、六维速览磁贴（`#identityTiles`）与目标地区对齐徽章（`#targetVerdictBadge`）的未完成态展示，杜绝网络/信誉探针尚未返回时提前闪现绿色「100 / 全项自洽 / 畅通 / 对齐」。
  - 补齐点击「重新检测」（`#btnRerun`）时的仪表盘、场景条与链路拓扑待确认态重置逻辑。

---

## [v7.1.0] - 2026-11-05

### Changed
- **图形化速览仪表盘重做（告别满屏文字段落）**：
  - **三节点实时链路拓扑图**：用「真实端侧 → 代理/出口节点 → 追踪锁定」可视化拓扑图与动态流向连线（分流漏底 / 协议栈代发 / `:443` 证书伪装实时着色）取代原先首屏四大段长篇文字侧写。
  - **六维图标化指标磁贴**：新增「时区与语言 / BGP 与黑名单 / 传输层协议栈 / 芯片与物理屏 / 沙箱防篡改 / 物理设备锁定」6 宫格速览磁贴，支持一键定位原始探针；完整自然语言侧写收纳至底部折叠抽屉（消除中文标点孤立换行）。
  - **SVG 圆环进度盘 + `自报 ≠ 实测` 胶囊对比**：评分升级为动态 SVG 圆环仪表与高危/可疑/通过三色计数块；「头号穿帮项」移除长句说明，改为一行一个 `macOS ≠ Linux SYN` / `海外 US ≠ 直连 CN` 直观对比胶囊。
  - **首屏直出六大业务场景彩色进度条**：在主诊断台下方直接呈现 AI、流媒体、社媒、免盾、金融支付与邮件信誉 6 组图标化通过率进度条。
  - **体检列表异常自动置顶 + 双栏色条卡片**：20 项核心风控体检改为双栏左侧色条卡片，高危与可疑项自动置顶并展示 `A ≠ B` 差异胶囊，修复指南改为编号步骤列表。

---

## [v7.0.0] - 2026-11-05

### Changed
- **全新视觉与渐进式诊断信息架构重构**：
  - **单行静默顶栏**：移除冗长副标题与分散的多边框按钮，将任意 IP 查询、视角切换、重新检测与工具组（打码 / 复制报告 / JSON / 主题切换）收敛为克制的单行工具条与顶部 `2px` 扫描进度线。
  - **双栏主诊断台（首屏零嵌套卡片）**：左侧为杂志档案式「网站眼里的你」自然语言侧写（将原先打断阅读节奏的四边框词条按钮重构为行内底纹 + 虚线下划线溯源词条，底部配无边框四维核心摘要与画像标签）；右侧集中呈现抗风控总分、20 段光谱条、Top-3 优先修复清单与三行核心遥测（出口纯净度、物理握手测距、跨站与硬件锁定码）。
  - **四分页渐进工作区**：新增「逐项风控体检 / 业务场景准入 / 分流与地区模拟 / 原始探针库」分段工作区切换器（带实时状态计数徽章），采用 `1px` 分割线网格替代多层嵌套边框卡片，消除单页超长堆叠带来的视觉噪音，并打通跨视图点击自动切换与高亮定位。
  - **前端加载瘦身**：移除未使用的 `430 KB` 第三方 UI 脚本阻塞加载，首屏解析更轻量。

---

## [v6.0.1] - 2026-11-05

### Fixed & Improved
- **高延迟住宅代理链路（RTT ≥ 400ms）与超大型 ISP 冷启动极速收敛**：
  - `probe.py`：`lookup_ip_geo` 改为常驻线程池并发竞速（`ip-api` + `ipwho.is` + 并行 `PTR` 反向解析），硬上限压缩至 `≤ 2.3s`。
  - `egress_intel.py`：移除 `with ThreadPoolExecutor` 阻塞式 `shutdown(wait=True)`，将主动 `:443` 证书抓取并入 Stage 1 与 8 大情报源并行执行，并为 Stage 1（`2.6s`）与 BGP ASN 档案查询（`1.8s`，`ip.guide` 与 RIPE `announced-prefixes` 并行竞速）设立严格硬挂钟预算，使冷启动大型宽带 ASN 全量信誉查询从 `9–15s` 降至 `< 3s`。
  - 前端 `runAll()` 将 `/api/who/me`、`/api/who/intel` 与多目标分流探针改为全并行渐进式渲染，消除慢代理串行超时累加。
- **多源出口元数据自动回填（消除单点故障）**：当主接口受代理抖动或策略限制时，自动使用 8 源情报共识（`/api/who/intel`）或客户端国际 GeoIP / Cloudflare Trace 备援回填出口 IP、国家、时区、经纬度与 ASN，杜绝顶栏 KPI 与六大场景卡片卡在「读取中 / 评估中」。
- **Fail-Closed 风控不确定性计分修正**：修复核心网络核验项因超时处于 `info` 未核验态时按 `0` 扣分误判 `100 A+` 的缺陷；未完成核验项现计入不确定性惩罚并封顶等级，明确提示可单项重测。
- **无被动 SYN 抓包时的物理光缆 RTT 测距兜底**：当连接复用、IPv6 或跨层代理未捕获被动 TCP SYN 握手耗时时，自动基于出口与服务端粗粒度大圆距离计算海底/陆地光缆物理直连基准（及全球光速上限），精准抓捕高 RTT 跨洲住宅代理中转。
- **指纹浏览器高阶矛盾与清存储缓存复活识别**：
  - 新增 Chromium 高熵 `Client Hints` 时空矛盾检测：识别自称现代 Chrome（`≥ 129`）或搭载 Apple Silicon（`Apple M1–M5`，出厂最低 `macOS 11+`）却将 `platformVersion` 伪装/回退为 `macOS 10.15` 的指纹浏览器配置漏洞。
  - 在「伪装环境自检」视角下，当检测到用户清空 `LocalStorage` 试图伪装新访客但被 `HTTP ETag` 缓存或 `IndexedDB` 认出回访时，自动纳入伪装破绽计分并置顶告警。
  - 修正公开威胁 CIDR 命中分类统计（覆盖 `attack` / `spam` / `tor` 网段库）与 `asnProfile` PeeringDB 展示字段映射。

---

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
