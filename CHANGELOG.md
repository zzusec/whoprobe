# Changelog

## [v7.9.15] - 2026-11-28

- 修复「防追踪 (`privacy`)」视角漏计真实请求 IP 分流漏底与代理穿帮项、导致暴露真实宽带 IP 仍获 91 分 A 级的严重评分倒挂：对齐双视角下的全量网络/协议/区域暴露核验，并在「防追踪」视角补齐「防指纹护盾与无状态留痕隔离 (`fp`)」计分项（识别跨站固定硬件指纹、局域网主机候选暴露及清除本地存储后的 ETag 缓存复活，同时保持「伪装自检」视角下常规浏览器回访零误判）。
- 新增真实端侧网络漏底「一票否决」扣分与封顶机制：无论处于「伪装自检」或「防追踪」视角，一旦观测到正向/反向大陆直连分流漏底 (`split`)、跨国或机房绕过型 WebRTC STUN 真实 IP 漏底 (`webrtc`) 或海外出口下的大陆递归/ECS 漏底 (`dns`)，立即叠加漏底重罚并将总分硬封顶于 `≤ 55`（`D/F` 级红环），并将漏底项置顶于首屏穿帮清单与拓扑告警条，确保「伪装越严密分数越高、漏出真实 IP 绝不虚高」。

---

## [v7.9.14] - 2026-11-27

- 首页增加原导航 HTTP 协议双端对照、文档解码前后字节数。已识别的 Cloudflare 回源只作为回源观测；缓存及缺失读数不当作访客协议证据。
- 修正旧探针在分流对照不足、ECS 部分返回、STUN 候选类型或地址族不同、TLS 复用时的误判。不新增外部探测目标。

---

## [v7.9.13] - 2026-11-27

- 修复 iOS / iPadOS 26 及 27+ 系统在 Safari 与第三方浏览器下被误识别为 `iOS 18.6` / `iOS 18.7` 的问题：Apple 自 iOS 26 起将 WebKit User-Agent 中的 `CPU iPhone OS` 字段永久冻结在 `18_6` / `18_7`（并在 Safari 中隐藏第 3 位补丁号如 `.1`），现双向对比 `CPU OS` 与 `Safari Version/` 三段式版本号（保留 `27.2.1` / `27.0.1` 等小版本），并对不含 `Version/` 的第三方 iOS 浏览器（`CriOS` / `FxiOS` / `EdgiOS` / `WKWebView`）通过系统 WebKit 原生特性（`::field-content`、`appearance: base-select`、`ariaNotify`、`anchor-name`）反推真实系统大版本。

---

## [v7.9.12] - 2026-11-27

- 修复海外手机卡在中国大陆国际漫游（S8HR 归属地路由，如新加坡 CMLink / 中国移动国际等）时被误报「国内外分流 (`海外 SG ≠ 直连 CN`)」的问题：`ipip.net` 属地解析仅匹配国家/省份字段（不再因运营商名含「中国移动/电信/联通」误标 `CN`），`iqiyi` 探针与 `analyzeExitSplit` 严格排除与主出口同 IP / 同子网 / 同运营商的回显，避免同一漫游出口自相矛盾扣分；同时补充国际漫游下基站 NITZ 自动下发驻留地时区（如 `Asia/Shanghai` vs `Asia/Singapore`）的说明与 iOS/Android 改法指引。

---

## [v7.9.11] - 2026-11-26

- 升级统一简洁页脚栏：展示隐私不留存说明、姊妹站「IP 类型与信誉查询」直达入口与「返回顶部」快捷操作。

---

## [v7.9.10] - 2026-11-26

- 移除页面底部页脚的 GitHub 外链入口，保持页面底部简洁无外跳干扰。

---

## [v7.9.9] - 2026-11-26

- 下线「跨站指纹与无痕缓存追踪抗性 (`fp`)」计分体检项（收敛为 23 项体检），避免常规浏览器二次回访因正常保留 HTTP ETag 或本地缓存被标红扣分。

---

## [v7.9.8] - 2026-11-26

- 修复跨境住宅代理在「往返延迟 (`rtt`)」上的两处漏检：① 补齐 `SYN→ClientHello` 反向远超 `HTTP RTT` 的双阶段 SOCKS5/CONNECT 握手膨胀判定（如 `HTTP 28ms vs 握手 317ms` 不再因负差值误判通过），剔除 `navigation` 预热缓存对 `preHttpRtt` 的污染，并校验 `ResourceTiming` 被干扰或本站在远距下的光速违例；② 新增本地同国 Cloudflare 边缘节点（如泰国 `BKK`、新加坡 `SIN`、东京 `NRT` 等）复用连接 RTT 交叉测距，精准识别源站在东京时跨境住宅代理多出的中转延迟。
- 修复规则分流在「多路由分流 (`split`)」上的漏检：替换已失效的 `forge.speedtest.cn`（404），新增国内主流流媒体边缘（`iqiyi.com`，命中 `GEOSITE,cn` 直连规则，规避代理规则集将 `ipip.net` 劫持走代理的绕过手法），补齐中文属地国家码映射，并将 `IPv4/IPv6` 独立双栈出口纳入统一分流桶计数（准确统计分流至 2/3+ 个不同出口）。

---

## [v7.9.7] - 2026-11-26

- 对齐 `isIntelConfirmedIsp` 与多源机房判定阈值（统一以 `hostE < 0.55` 与 `hostE >= 0.55` 为分界，消除 `0.50 ~ 0.55` 判定死区），确保部分上游超时、2/5 数据源因商业租赁主体标注 `hosting`（`hostE ≈ 0.504`）时仍与六大场景模拟器一致收敛为「商业租赁段（挂靠宽带 ASN）」。

---

## [v7.9.6] - 2026-11-26

- 消除多源情报与首包单源 GeoIP 在「机房 vs 宽带」上的页面内自相矛盾：当 8 源加权投票与 PeeringDB 入向流量确认自治系统为宽带运营商（`hostE < 0.50` 且 `cls = isp/mobile`）时，双向修正首包单源误标的 `R.netKind = "dc"`，不再把挂靠宽带 ASN 的网段误判为高危云服务器机房。
- 扩充商业 IP 租赁与托管经纪商识别库（覆盖 `PF IPv4 Borrower`、`PacketFabric`、`IPv4.Global`、`Unitas Global` 等），精准识别挂靠宽带运营商 ASN 宣告的「双 ISP 商业租赁/专线地址段」并在 `lease` 项与拓扑胶囊中明确提示。

---

## [v7.9.5] - 2026-11-26

- 彻底取消弹窗与系统服务提示：完全停用 `popupblk` 的 `window.open` 探测，移动端免弹窗跳过 `PublicKeyCredential`（消除华为/国产无 GMS 机型弹出「启用 Google Play 服务」提示）与蓝牙状态查询，HTML 响应头新增 `encrypted-media=(), bluetooth=(), publickey-credentials-get=(), publickey-credentials-create=()` 并加入 `notranslate` 元标签。
- 修复安卓真机蜂窝网络下 `tamper`（「环境篡改检测」）高危误报：兼容挖孔屏/虚拟导航栏导致的 `screen.height` 与 CSS `device-height` 系统栏高度差及移动端系统字体缩放，规避安卓 `fonts.xml` PostScript 字体别名在 `local()` 与 Canvas 族名间的固有差异，并兼容单语种系统 Chrome 默认附带低权重 `en-US,en` 兜底 `Accept-Language` 请求头的原生行为。

---

## [v7.9.4] - 2026-11-26

- 彻底消除页面加载时的三类浏览器弹窗与权限提示：① 将 `popupblk` 改为纯手动点击自检，首屏不再自动调用 `window.open("about:blank")`（消除窗口闪烁及地址栏「已拦截弹出式窗口」提示）；② 服务端对 HTML 页面下发 `Permissions-Policy: local-network-access=(), local-network=(), loopback-network=()` 等策略头，静默阻止 Chrome 142–148 在跨域探针域名被 DNS 去广告或 Fake-IP 解析至本地网段时弹出「想要查找并连接到本地网络上的设备」权限框；③ Android / Linux / 触屏环境下免弹窗跳过需设备标识符授权的 Widevine 查询（消除「想要播放受保护的内容」权限弹窗）。

---

## [v7.9.3] - 2026-11-26

- 区分实时 DNSBL 中的「25 端口邮件反垃圾库 (`mail`)」与「攻击/爆破/开放代理/Tor 黑名单 (`abuse` / `tor`)」：动态家庭宽带仅单点命中 1 家纯邮件 RBL（如 `Barracuda`）且无其他风险时，仅影响 SMTP 25 端口发信评分，不再将核心体检 `reputation` 误判为高危破绽，也不再连坐扣减 AI、社媒、Turnstile 免盾与支付场景通过率。
- 修正 `reputation` 异常胶囊文案，准确展示命中黑名单/威胁段/脏邻居数量，避免出现「纯净 94 · 脏邻 0」与高危红标自相矛盾的展示。

---

## [v7.9.2] - 2026-11-26

- 修复手机 5G / 家宽 NAT 出口因 Shodan 未收录开放端口或个别免费情报源超时使 `purity.uncertain` 为真时，前端将 `reputation`（「欺诈风险、黑名单与同 /24 脏邻居连坐」）误判为「网络探针超时 / 待重测」并扣分降级的缺陷：具备有效多源与黑名单覆盖（`ratio ≥ 0.55`）时正常采用信誉评分并标注实际覆盖项数。
- 区分客户端 `/api/who/intel` 请求超时与服务端上游信誉源真正覆盖不足的提示文案，且覆盖率低于阈值（`< 0.55`）的降级结果不再写入 `INTEL_CACHE` 缓存。

---

## [v7.9.1] - 2026-11-25

- 跨线程与 iframe 只对照两侧实际读取到的值；缺值标为未核对，数值确实不同仍提示。浮点 NaN 架构推测只作参考，不单独扣分。
- 缺少 TCP 握手对照时，HTTP 响应偏慢只提示延迟，不判定多跳或扣分；ICE 候选出现耗时不当作 UDP RTT。保留能直接比较的时序或候选地址差异。

---

## [v7.9.0] - 2026-11-25

- 新增「网站能看到什么」：本次页面导航的 HTTP 收据、入站对端与协议、匹配到同一连接的握手，以及浏览器脚本可读与情报推断分栏。敏感请求值和收据均不进入分享。
- Linux IPv4/IPv6 TCP 采集按可信入口四元组关联；不再按公网 IP 回填其他访问的传输指纹。多次 TLS 握手仅在本轮采样合并。
- 可选配置自有端点做双栈及实际 H3、权威 DNS + HTTPS、TURN 数据通道、跨站存储隔离联测。未配置或没有可确认数据时标明未测。
- 显示 BGP 起源历史、情报来源覆盖率；修正双栈双失败、WebRTC 空候选、TLS 提议和 HTTP/3 缺测的过度结论，主动出站回探改为默认关闭。

---

## [v7.8.1] - 2026-11-25

### Changed — 管理后台改为 `/admin?k=<token>` 隐身直达令牌模式（无令牌访问直接 404）
- 移除公开可见的密码登录框：未携带有效 `?k=<16位密钥>`（且无已签发会话 Cookie）访问 `/admin` 或任何 `/api/who/admin/*` 接口时，服务端一律返回标准 `404 Not Found`，对目录扫描器完全隐身。
- 携带正确 `?k=<token>` 打开链接即可零点击直达后台看板（自动签发 14 天 `HttpOnly; SameSite=Strict; Secure` Cookie，同时支持无痕窗口 `X-Admin-Key` 透传），全页强制 `Referrer-Policy: no-referrer` 确保外跳链接绝不泄露 URL 中的密钥参数。

---

## [v7.8.0] - 2026-11-25

### Added — 自托管管理后台：每日访客统计、真实来访 IP 明细与分享页画面预览 (`/admin`)
- **按需启用的零依赖管理审计引擎 (`admin_store.py` + `probe.py`)**：
  - 默认未配置口令时 `/admin` 与全部 `/api/who/admin/*` 接口均返回 `404` 且零日志落盘；当通过 `--admin-token`、`--admin-token-file`、`WHOPROBE_ADMIN_TOKEN` 或 `systemd` `LoadCredential=admin_token:...` 配置口令后自动开启。
  - 登录采用 `hmac.compare_digest` 恒定时间比对、按 IP 防暴力破解限流（10 分钟 8 次上限）与 `HMAC-SHA256` 签名的 `HttpOnly; SameSite=Strict` 会话 Cookie（14 天免重复输密）；SQLite WAL 库自动执行 90 天与 20 万行封顶清理，且公开分享页 `/r/<id>` 对外部访客依旧保持 100% 零 IP 隐私隔离。
- **三合一可视化管理控制台 (`static/admin.html` + `static/admin.js`)**：
  - **每日访问趋势与核心指标**：实时展示今日/昨日/近 7 日/近 30 日独立访客人数（UV）与总访问次数（PV）、热门来源地区及 **30 天交互式柱状趋势图**（点击任意一天即可下钻筛选当天全部来访 IP）。
  - **实时访客与 IP 明细流**：记录每次「主页检测」「打开分享页」「生成分享页」「查外部 IP」的时间（`UTC+8`）、真实公网 IP（支持一键复制、按单 IP 过滤轨迹、一键穿透查询该 IP 信誉）、归属省市与 ASN/ISP、端侧系统/浏览器/被动 TCP 栈。
  - **分享页画廊与全真画面预览抽屉**：在访客明细行或「分享页总览」标签点击任意分享码 `#id`，即可在后台弹窗内直接原样渲染该分享页的 **`/r/<id>.svg` 动态矢量成绩卡**、六大业务场景通过率、异常扣分明细，以及「谁生成了该分享页 + 历史每次是谁用什么 IP/设备打开的」，并支持管理员一键删除违规或测试分享快照。

---

## [v7.7.4] - 2026-11-25

### Changed — 拓扑图「真实端侧」卡片直接展示真实端侧 IP（分流漏底 / STUN 漏底 / 直连终端）
- 在首屏三跳链路拓扑图左侧「真实端侧」节点主行直接展示真实客户端 IP（优先展示国内规则分流直连泄漏 IP `ex_cn.ip`、WebRTC `STUN` 穿透泄漏 IP 或无代理直连终端 IP；全局+TUN 严密隐藏未漏底时明确标识 `未暴露真实IP` / `IP已隐藏`），副行同步展示归属运营商、系统与时区，且完全兼容顶栏一键「打码」与公开分享页 `/r/<id>` 零 IP 脱敏。

---

## [v7.7.3] - 2026-11-25

### Fixed — 修复手机 5G 蜂窝网络下「物理测距 `HTTP ≫ 握手`」高危中转误报
- **消除 `SYN` 重传计时覆盖与共享 CGNAT 跨用户极小值粘滞 (`probe.py` · `LinuxPacketSniffer` + `update_handshake_rtt_window`)**：
  - 同一连接发生 TCP `SYN` 重传（相同 `src_ip:src_port` 与 `tcp_seq`）时不再覆盖首次 `SYN` 时间戳且跳过重传歧义连接的握手测时，避免重传 `SYN` 与首轮 `ClientHello` 相减得出虚假极小握手 RTT；
  - 将共享公网 IP 的 `minHandshakeRttMs` 从 180 秒历史全局最小值改为 **12 秒新鲜滑动窗口中位数**，杜绝 5G CGNAT 地址池内其他邻近基站用户或偶发单包极值污染后续检测。
- **并发风暴前空闲预采样与 4G/5G 空口抖动物理模型 (`static/app.js` · `measureCleanPrePing` + `classifyHandshakeGap`)**：
  - 在启动 20 路并发分流/DNS/扩展探测挤占手机 5G 上行 PDCP 队列前，先在空闲热连接上完成轻量预采样并结合 `NavigationTiming` 首包往返；
  - 对协议栈吻合且无分流泄漏的原生蜂窝移动网络（`R.netKind === "mobile"`），兼容运营商省级 UPF/PEP 分段握手与 5G NR 空口 DRX/HARQ 调度产生的正常波动，同时保留对机房 VPS 代发握手（`1~18ms`）或协议栈错配代理的精准抓捕。

---

## [v7.7.2] - 2026-11-25

### Fixed — 修复 Mac 触控板快速划动「机械轨迹」误报与「防追踪」视角胶囊/副标题混用
- **消除桌面触控板单次划动与热点切换瞬间 `bot` 误报「机械轨迹」(`static/app.js`)**：
  - 加宽 `inputStraightRatio` 采样窗口（16 点长跨度、步进 8、最小弦长 80px）并结合速度变异系数 `bioConstVel` 双重确认，避免 MacBook 触控板指针加速平滑下的短促快速甩动被误判为脚本直线插值；
  - 单条孤立的 `headlessSoft`（如刚切换手机热点时 Chrome NQE 尚未采样完成导致 `navigator.connection.rtt === 0`）不再单独触发 `bot` 警告扣分（需 ≥2 项弱信号叠加）；并补齐 `getVisualConflict("bot")` 各警告子项专属胶囊标签。
- **修正「防追踪」视角下 `fp` 差异胶囊与专属提示文案 (`static/app.js` + `static/index.html`)**：
  - 修复未清空 `LocalStorage`（`4/4 项存储认出回访`）却显示 `清空存储 ≠ ETag 命中` 的逻辑错误（现仅在 `R.cacheResurrected` 为真时显示，常规回访准确显示 `ETag/存储跨会话锁定`）；
  - 区分「伪装自检」与「防追踪」视角的卡片标题（`抗风控健康度` vs `防追踪隐私度`）、副标题说明及历史对比基线（`SK.prevChecks` 按视角独立存储，不再跨模式混算增减）。

---

## [v7.7.1] - 2026-11-25

### Fixed — 修复真机 5G 蜂窝网络（CGNAT）下「TSval 时钟突变」高危误报与小屏标题折行
- **消除 5G 蜂窝 UPF / CGNAT 网关下 `synSpoofSuspect` 误报 (`probe.py` · `evaluate_tcp_continuity`)**：
  - **原因 1（运营商网关剥离 `TSopt`）**：国内三大运营商 5G UPF / CGNAT（如 `36.21.*` 电信蜂窝池）常在返回的 `SYN-ACK` 中剥离 TCP Timestamp 选项（或在硬件 NAT Fastpath 剥离数据包 TCP 选项）；iPhone（iOS）严格遵循 RFC 7323 §3.2 在 `ClientHello` 中不再携带 `TSopt`，旧逻辑将 `syn_had_ts && hello_tsval is None` 误判为无状态 SYN 改包。
  - **原因 2（无符号减法下溢与 1MHz 高频时钟）**：旧逻辑使用 `(hello_tsval - syn_tsval) & 0xFFFFFFFF`，当 CGNAT 多转发核间存在 `-1 ~ -5ms` 微小计数偏置时无符号下溢为 `4.29×10⁹`，且 `25kHz` 上限会误伤 `1MHz` 微秒级 RFC 7323 时钟与 5G 空口突发释放。现改为 32 位有符号模差值，兼容微小负向抖动与最高 `2.5MHz` 高精度时钟。
  - **原因 3（共享 CGNAT IP 跨连接粘滞与端口复用串扰）**：`LinuxPacketSniffer` 现严格校验 `tcp_seq == (syn_seq + 1) & 0xFFFFFFFF` 锁定同一 TCP 套接字，且每次新 `SYN` 重置 `synSpoofSuspect`，杜绝同 CGNAT 公网 IP 下其他会话串扰；同时新增同连接 `TTL` 跨包跳变（`≥30`）检测以精准锁定真实 `osfuscate` 单包改包。
- **WebKit / Safari `ice-ufrag` 长度兼容 (`static/app.js`)**：在 `Safari` / `iOSWebKit` 上仅当出现 Firefox 专属 `THIS_IS_SDPARTA` 签名时才报 SDP 引擎冲突，兼容不同 WebKit 版本的 `ice-ufrag` 长度。
- **移动端首屏健康度卡片顶栏防断字 (`static/index.html`)**：修复小屏手机同时展示「分享结果」「比上次多 X 处」「伪装自检」时，将「抗风控健康度」挤成单字折行（`度` / `果` / `检`）的排版问题。

---

## [v7.7.0] - 2026-11-25

### Added — 9 项协议栈深水区、五界沙箱、GPU ALU 尾数与行为生物动力学探针（182 → 191 项）
将 Cloudflare Enterprise Bot Management、Akamai `sensor_data`、TikTok `webmssdk` 与 CreepJS 最底层的传输层加密首包解密、跨连接洗牌验真及多界线程对比全量零依赖落地：
- **RFC 9001 QUIC v1/v2 Initial 无私钥解密与 `JA4Q` 传输参数指纹 (`quicpar` · `probe.py` + `static/app.js`)**：
  - 服务端纯 Python 标准库实现 AES-128-ECB 头部保护脱壳、AES-128-GCM 认证解密、HKDF-Expand-Label 初始密钥派生与跨 UDP 包乱序 `CRYPTO` 帧重组（完整兼容 Chrome 后量子 `X25519MLKEM768` 双包分片 `ClientHello`）。
  - 提取 `JA4Q` (`q13...`) 与 `0x0039 quic_transport_parameters`（流控窗口、`active_connection_id_limit`、`version_information` 与 `31*N+27` GREASE 参数），精准区分 Chromium `quiche`、Firefox `neqo`、Apple `nw_quic` 与代理客户端 `quic-go`（Sing-box / Mihomo / Hysteria2 代发 UDP 时直接计入 `conn` 协议穿帮）。
- **跨连接 TLS `ClientHello` 扩展随机洗牌与 PSK 会话恢复验真 (`tlsperm`)**：按 `ClientHello.random` 去重比对同一访客连续多次独立 TLS 握手的扩展排列顺序；自称现代 Chromium（110+ 默认每次连接随机打乱扩展顺序）却连续呈现 100% 静态雷同顺序时，直接识破静态 `JA3` / `uTLS` 模板伪造。
- **服务端主动 RFC 6455 WebSocket `Ping → Pong` 控制帧测距 (`wsping`)**：`/api/who/ws-ping` 在握手完成后由服务端主动连发两轮 `0x89 Ping` 控制帧，测量浏览器底层 C++ 网络进程直接回传 `0x8A Pong` 的纯传输耗时（绕过后台标签页或插件对页面 JS 主线程的节流干扰），与 `HTTP RTT` 及 `TCP SYN RTT` 四维互校。
- **WebRTC SDP `ice-ufrag` 长度与 `o=` Origin 引擎互证 (`ufrag`)**：核对 SDP Offer 的 `o=` 行（Firefox 必含 `THIS_IS_SDPARTA`，Chromium/WebKit 为 `o=-`）与 `a=ice-ufrag` 随机串长度（`libwebrtc` 恒为 4 字符，Firefox `nICEr` 恒为 8 字符），专杀跨内核套壳伪装。
- **JS 引擎 JIT 编译预热加速曲线 (`jitwarm`)**：对比 24 组冷态解释器函数与 25,000+ 次迭代后 Maglev / TurboFan / FTL 机器码的等效执行加速倍数，结合 `WebAssembly` 可用性识别 iOS 锁定模式（Lockdown Mode）或 `--jitless` 容器沙箱。
- **WebGL `highp` 着色器 ALU 尾数与压缩纹理硬件架构核验 (`gpufp`)**：运行自定义片元着色器提取 GPU 超越函数（`sin` / `exp2` / `atan` / `inversesqrt`）硬件舍入尾数哈希，并交叉核验压缩纹理硬件格式（Apple M/A 系必含 `ASTC`，桌面 NVIDIA/AMD 含 `S3TC`/`BPTC` 不含 `ASTC`），拆穿仅 Hook `UNMASKED_RENDERER_WEBGL` 字符串的显卡改名插件。
- **第 4 界 `SharedWorker` 与第 5 界 `ServiceWorker` 跨界核验 (`swrealm`)**：新增同源 `/sw-probe.js`，在独立作用域 `./__wp_sw_probe__/` 即采即销（`MessageChannel` 采样后立即 `unregister()`，零页面拦截残留），比对主线程与共享/服务线程的 `UA`、`platform`、核数、时区、语言与显卡。
- **精细行为生物动力学 (`biodyn`)**：被动统计扫描期鼠标移动速度变异系数（CV，区分真人加减速与脚本恒速线性插值）、触控板连续像素流 vs 物理滚轮 100/120px 离散步进，以及按键 `keydown→keyup` 驻留时间（`<1.5ms` 实锤脚本瞬时派发按键）。
- **本机代理与指纹浏览器控制端口手动自检 (`localport`)**：仅在用户手动点击按钮时探测 `127.0.0.1` 常见代理口（7890/7891/9090 Clash、10808 v2rayN、1080 SOCKS、2080 Sing-box）与指纹浏览器 API 口（50325 AdsPower、54345 比特浏览器、35000 Multilogin、9222 Chrome CDP），保持首屏零本地网络权限弹窗。

---

## [v7.6.0] - 2026-11-25

### Added — 攻克 HTTP/2 Akamai 原始帧指纹与无打扰启动参数副作用检测（174 → 182 项）
将此前因 Nginx 终止 TLS 或担心打扰用户而未纳入的高阶检测手段全部无感落地，并补齐跨线程 WebGL 与 SDP/Intl 深度核验：
- **服务端 HTTP/2 Akamai 原始帧指纹 (`h2akamai` · `probe.py`)**：
  - `probe.py` 内置零依赖 `TLSBridgeServer` (`--tls-bridge-port`) 与 RFC 9113 / RFC 7541 HPACK 伪头解析器，支持上游 Nginx `stream` SNI 路由与 `PROXY protocol v1` 透传、多域名 SNI 证书切换（兼容 `systemd` `LoadCredential` 最小权限加载）及 Nginx `h2c` / `http/1.1` 双后端自动桥接（上游可配 `backup` 无缝容灾）。
  - 在转发首包前无损提取客户端原始 `SETTINGS` 参数顺序与值、连接级 `WINDOW_UPDATE` 增量、`PRIORITY` / `HEADERS` 流优先级与伪头部顺序（如 Chromium `m,a,s,p`、Firefox `m,p,a,s`、Safari WebKit `m,s,p,a`、Go `x/net/http2`、curl `nghttp2`、Python `hyper-h2`），拼装标准 `<SETTINGS>|<WU>|<PRIORITY>|<PSEUDO>` Akamai 指纹并与 UA 自报内核交叉核验（不一致时直接计入 `conn` 高危穿帮）。
- **IPC 洪泛保护开关无感检测 (`ipcflood`)**：新增 `/api/who/blank` 轻量同源空白页，在隐藏 `iframe` 内 12ms 同步执行 260 次 `history.replaceState`（零主页面 URL 变动、零耗时等待）：正常 Chromium 在 ~200 次触发 Blink `FloodGuard` 限流，开启 Puppeteer / Playwright 默认参数 `--disable-ipc-flooding-protection` 时 260 次全量放行。
- **CSP 内容安全策略绕过检测 (`cspbypass`)**：在隔离 `srcdoc` `iframe` 内声明 `script-src 'none'` 并放置内联探针脚本，毫秒级零误报实锤 CDP `Page.setBypassCSP` / Playwright `bypassCSP: true`。
- **无手势弹窗拦截自动实测 (`popupblk`)**：仅在页面首次加载且 `navigator.userActivation.isActive === false` 时静默测试 `window.open` 是否被默认拦截（若放行则同帧立即 `w.close()` 关闭；用户手动点「重新检测」处于激活窗口期时自动复用首测结果，绝不误弹窗），识别 `--disable-popup-blocking`。
- **Worker `OffscreenCanvas` 显卡跨线程核验 (`glworker`)**：在独立 Web Worker 内读取 WebGL `UNMASKED_RENDERER_WEBGL` 并与主线程显卡比对（CreepJS `hasBadWebGL` 同款），专杀只 Hook 主页面 WebGL 的 stealth 插件与指纹浏览器。
- **WebRTC SDP 协议栈与 DTLS/SCTP 模板 (`rtcsdp`)**：纯本地零外网请求生成 Offer SDP，提取 `ice-options`、DTLS 哈希算法、SCTP `max-message-size` 与 RTP 扩展模板签名。
- **Intl 六大构造器默认区域一致性 (`intldeep`)**：比对 `DateTimeFormat`、`NumberFormat`、`RelativeTimeFormat`、`PluralRules`、`DisplayNames` 与 `ListFormat` 默认主语种，抓捕半吊子语言注入。
- **原生 `Error.stack` 调用栈语法互证 (`stackfmt`)**：校验 V8 `'    at '` 与 SpiderMonkey/JSC `'@'` 堆栈格式及 `Error.captureStackTrace`，反证跨引擎 UA 伪装。

---

## [v7.5.0] - 2026-11-25

### Added — 对标大厂风控 SDK 与开源检测项目的 12 项新探针（162 → 174 项）
参考 TikTok webmssdk、Akamai Bot Manager sensor_data、PerimeterX/HUMAN、DataDome、Cloudflare 挑战脚本，以及 GitHub 开源 `fingerprintjs/BotD`、`fingerprintjs`（sources）、`abrahamjuliot/CreepJS`、bot.sannysoft.com、`rebrowser-bot-detector`、`kaliiiiiiiiii/brotector` 的检测清单：
- **自动化 / 爬虫框架全局标记全量扫描 (`autokeys`)**：Selenium / ChromeDriver `$cdc_` 正则 / Watir / PhantomJS / Phantomas / Nightmare / Cypress / TestCafe / WebdriverIO / Playwright / Puppeteer `exposeFunction` 绑定 / CEF / CefSharp / Awesomium / FMiner / Geb / Spynner / Sequentum 等 59 个标记。
- **宿主运行时 (`jsenv`)**：Node `process`/`Buffer`/`require`、Electron、NW.js、jsdom，以及 WKWebView / React Native / Flutter / 微信 JSBridge 应用内容器。
- **无头浏览器渲染特征 (`headless`)**：HeadlessChrome 品牌、破损图片 0×0、PDF 查看器与 plugins 矛盾、`connection.rtt=0`、语音引擎为空、800×600 / 1280×720 默认视口、软件 GPU。
- **隐身补丁残留 (`stealth`)**：`navigator.webdriver` 被删成 `undefined`、`window.chrome` 事后注入 / `loadTimes`·`csi` 伪造、srcdoc iframe 代理回主窗口、原生 getter 非法调用错误栈中的 Proxy / 扩展帧、伪造 PluginArray。
- **页面焦点与用户激活 (`focus`)**：`document.hasFocus()`、`visibilityState`、`navigator.userActivation`。
- **浮点 NaN 位模式 CPU 架构 (`cpuarch`)**：x86 0xFF / ARM 0x7F，对照 Client Hints / UA，识破手机 UA 跑在 x86 模拟器 / 云手机。
- **CSS 系统字体关键字与系统色 (`sysfont`)**：`font: caption/menu/...` 解析出的宿主系统字体反证伪装系统。
- **navigator 厂商属性一致性 (`navprops`)**：vendor / productSub / `eval.toString` 长度 / appVersion / oscpu / buildID / userAgentData / H.264（开源 Chromium 冒充 Google Chrome）/ ApplePaySession / 15 种 vendorFlavors。
- **Date 时区名称语言 (`tzname`)**：`Date().toString()` 时区名暴露浏览器界面语言，与 `navigator.languages` 不一致时计入「系统底层语种」。
- **Sec-CH-UA GREASE 品牌算法校验 (`chgrease`)**：按 Chromium「主版本号为种子」算法复算 `Not?A?Brand` 与版本（8/99/24），比对 HTTP 头与 JS。
- **AI / 社媒平台地区准入 (`aigeo`)**：按 ChatGPT / Claude 实际分流出口比对 OpenAI / Anthropic / Gemini / TikTok 不服务地区；TikTok 受限地区同时计入「社媒注册」场景。
- **AudioContext 基础延迟指纹 (`audiolat`)**。

### Changed — 交互与视觉
- 体检卡片：异常项摘要改为中性正文色（严重度只由左侧色条、图标与差异标签表达），通过项改为紧凑浅色卡片，异常一眼可见；点击卡片空白处即可展开 / 收起改法，展开后摘要不再截断；「重测」「改法 / 原理」改为轻量图标按钮并带展开箭头与 `aria-expanded`。
- 手机端：卡片操作按钮移到摘要下方，标题与摘要获得整行宽度；场景卡片与六维速览标题不再被截断。
- 诊断标签栏吸顶（自动避让桌面端吸顶页眉高度），手机端三等分短标签；切换标签时自动回到面板顶部；支持 ←/→/Home/End 键盘切换（WAI-ARIA Tabs）。
- 「仅看异常 / 已通过」筛选按钮显示实时数量；差异标签同步显示光速违例、代理端口、代理转发头、CDP 附着等新结论。
- `bot` / `ua` / `fpb` / `syslang` 核验融合上述新信号。

---

## [v7.4.0] - 2026-11-25

### Added — 14 项新检测手段（148 → 162 项探针）
- **出口 IP 实时代理 / 远控端口回扫 (`portscan` · `egress_intel.py`)**：服务端以单线程 `selectors` 并发 `connect` 出口 IP 的 17 个常见代理（SOCKS 1080 / Squid 3128 / HTTP 8080·8888 / Privoxy 8118 / Shadowsocks 8388 / Clash 7890 / V2Ray 10808 / Tor 9050）、VPN（OpenVPN 1194 / PPTP 1723）、远控（SSH 22 / RDP 3389 / VNC 5900）与面板（X-UI 54321 / 8443）端口，只被动读取欢迎横幅（IP 自动脱敏）、不发送任何载荷；≥70% 端口同时“开放”时判定为 SYN-Proxy/Tarpit 并放弃结论。命中代理/VPN 端口会写入多源投票。**防滥用：仅对访客自身出口执行，`?ip=` 查询任意 IP 时不扫描；`--no-active-probe` 一并关闭。**
- **全球 18 区域 RTT 光速三角测距 (`rttgeo`)**：浏览器对 AWS DynamoDB 全球 18 个区域（含北京）`/ping` 端点做冷启动 + 2 次热连接测距；任一区域往返低于「出口 IP 登记地 → 该区域」光纤物理下限（≈ 距离/100 ms，已扣 800 km 定位误差）即判定「光速违例」：该路流量未经当前出口（规则分流直连）或出口属跨洲广播 IP。
- **代理转发头与 HTTPS 中间人注入 (`proxyhdr` · `probe.py`)**：`/api/who/me` 新增 `proxyHeaders`，识别 TLS 终止后仍出现的 `Via` / `Forwarded` / 预置 `X-Forwarded-For` 跳数 / `CF-Worker` / 非可信来源 `CF-*` 等 30 余种中间层头（仅返回头名称与脱敏 Via）。
- **Accept-Language q 权重格式核验 (`h_lfmt`)**：q 值递减、格式合法性及语种是否超出 `navigator.languages`。
- **夏令时规则与历史时区偏移核验 (`tzdst`)**：今年冬/夏与 2005/2015 共 5 个时点比对 `Date.getTimezoneOffset` 与 Intl IANA 规则。
- **Date 时钟源内部一致性 (`clocksrc`)**：`Date.now` / `new Date` / `Date.parse(ISO)` 互校，并展示单调时钟漂移与服务端校时。
- **CSS 媒体查询 vs JS 屏幕读数 (`mqscreen`)**：二分反推 `device-width/height`、`resolution` 与 `orientation`，拆穿只改 JS `screen` / `devicePixelRatio` 的插件。
- **移动端仿真一致性 (`mobilex`)**：自称手机/平板时核对触控点、主指针、悬停、`ontouchstart`、屏幕短边与 GPU 型号，识别 DevTools 设备模拟。
- **WebAssembly 特性矩阵与内核代际 (`wasmfeat`)**：13 项 WASM 提案字节码 + JSPI，反推 V8 / SpiderMonkey 最低代际，虚报新版 Chrome/Firefox 却缺 GC / 尾调用时计入指纹浏览器矛盾。
- **FontFace `local()` 字体旁路核验 (`fontlocal`)**：17 款系统标志性字体多名称变体加载，与 Canvas 字体探测交叉比对并核验自报系统必备字体。
- **CDP 调试协议附着与注入帧 (`cdp`)**：`Error.stack` getter + `console.debug` 序列化副作用、Puppeteer/Playwright 注入帧、Selenium DOM 标记与无头通知权限矛盾。
- **窗口外框与无头渲染尺寸 (`winchrome`)**：外框为 0 / 与视口相同（无头、Kiosk）与开发者工具停靠识别，已排除缩放、全屏与 PWA。
- **无痕 / 隐私窗口识别 (`incog`)**：Chromium 配额 vs 堆上限、Safari/Firefox OPFS 异常侧信道。
- **交互事件可信度与轨迹 (`input`)**：被动记录检测期间输入事件，`isTrusted=false` 合成事件直接计入自动化痕迹，并统计机械直线轨迹占比。

### Changed
- 核心核验融合新信号：`reality` 更名为「出口主动回探（:443 Reality 与代理端口）」；`rtt` 叠加光速违例；`conn` 叠加中间层代理头；`tamper` 叠加媒体查询 / 夏令时 / Date Hook / 字体 Hook / 语言头改写；`fpb` 叠加 WASM 代际与本地字体系统矛盾；`ua` 叠加移动端仿真矛盾；`bot` 新增 CDP 附着、无头外框（警告）与合成事件（高危）分级。
- 自检 (`--self-test`) 新增代理头识别、端口回扫汇总/SYN-Proxy 防误报、横幅脱敏与 `/api/who/me` `proxyHeaders` 用例。

---

## [v7.3.3] - 2026-11-21

### Fixed
- **消除上游路由器/CGNAT 擦除 IPv4 `DF` 位时的 `DF 包头矛盾` 误报 (`static/app.js`)**：
  - 当抓包实测 TCP SYN 窗口与选项序列本身即为原生 Linux 协议栈（`osFamily === "linux"` 或 `IPID === 0`）且 TSval 内核时钟连续无改包特征时，不再因途经运营商/云网关擦除 `DF` 位而误判「自报 Linux 系统但首包 DF=0」扣分；仅在真实发包栈并非 Linux（如 BSD/macOS `DF=0` 伪装 Linux UA）时告警。
- **区分「伪装自检」与「防追踪」模式下的同窗口持久化会话提示 (`static/app.js`)**：
  - 在「伪装自检」模式下，只要未发生「仅清 LocalStorage 却遗漏 HTTP ETag 缓存复活（`cacheResurrected`）」的防关联穿帮，同窗口正常刷新保留会话与固定硬件码展示为中性说明（避免正常持久化养号环境被误认为跨窗口串号报错）；「防追踪」模式仍严格提示跨站追踪风险。

---

## [v7.3.2] - 2026-11-20

### Fixed
- **补齐全球 454 项 IANA `zone1970.tab` 与 V8/ICU CLDR 时区主别名国家映射 (`static/app.js`)**：
  - 修复真实 Chromium / V8 浏览器在阿根廷（`Intl.DateTimeFormat` 按 Unicode CLDR 规范返回 `America/Buenos_Aires`）、尼泊尔（`Asia/Katmandu`）及多时区省州城市出口下因 `TZ_CC` 漏项误判「系统时区指向未知地区（`Buenos Aires ≠ Buenos Aires`）」的问题。

---

## [v7.3.1] - 2026-11-06

### Changed
- **顶栏新增按访问域名动态映射的「我的 IP」姐妹站切换标签 (`static/index.html` + `static/app.js`)**：
  - 与 `ip.<主域名>` 顶栏双站切换栏对称，在顶部品牌栏新增 `[ WhoProbe | 我的 IP ]` 导航标签（`siblingIpHref(location.hostname)`）。
  - 根据当前访问入口 `who.<主域名>` 自动推导跳转到同主域下的 `https://ip.<主域名>/`（附带 `referrerpolicy="no-referrer"`，开源仓库中零私有域名硬编码），同时恢复下方诊断区清爽的 3 标签结构。

---

## [v7.3.0] - 2026-11-06

### Added
- **新增「我的 IP」独立标签页 (`static/index.html` + `static/app.js`)**：
  - 在下方诊断工作区（紧邻「逐项风控体检」）新增 `我的 IP` 标签页（支持从拓扑图主出口卡片或外部 IP 检视横幅一键直达），零额外请求聚合展示完整公网出口档案。
  - **主出口总览与 8 维核心属性**：大号等宽显示 IPv4/IPv6 地址、一键复制 IP 或完整归属摘要、支持全局隐私打码（`maskable`）；直观呈现国家/省州/城市、ASN 与运营商、原生 IP / 广播 IP（RDAP 注册国比对）、RPKI 与 BGP 租赁状态、IP 所属时区、参考坐标与物理握手延迟、反向 PTR 主机名及 `:443` 证书/端口暴露状态。
  - **双栈、WebRTC 与 DNS 通道速览**：并列展示纯 IPv4 独立出口、纯 IPv6 独立出口（含 EUI-64 网卡 MAC 隐私检测）、WebRTC STUN 反射地址与局域网 mDNS、递归 DNS 解析器与 ECS 状态，点击任意卡片即可复制对应地址。
  - **纯净度加扣分账单与 8 源情报对比**：可视化展示基准分加扣分账单、机房/代理/VPN/Tor/DNSBL 投票统计及各家独立情报源逐项判定卡片；公开脱敏分享视图（`/r/<id>`）自动启用隐私隔离保护，绝不暴露原始 IP。

---

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
