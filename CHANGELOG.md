# Changelog

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
