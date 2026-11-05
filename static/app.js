/* WhoProbe v6.0 — 148-Probe L3–L7 Forensic, Active :443 Reality & BGP Egress Intelligence Engine */
(function () {
  "use strict";

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
  const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const within = (p, ms, fb = null) => Promise.race([Promise.resolve(p).catch(() => fb), new Promise(r => setTimeout(() => r(fb), ms))]);
  const mq = q => { try { return window.matchMedia(q).matches; } catch (e) { return false; } };

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
    del(k) { try { localStorage.removeItem(k); } catch (e) {} }
  };
  const SK = {
    theme: "whoprobe:theme",
    mask: "whoprobe:mask",
    scene: "whoprobe:scene",
    target: "whoprobe:target",
    lastVisit: "whoprobe:last",
    prevChecks: "whoprobe:prev",
    history: "whoprobe:hist",
    traceTag: "whoprobe:tag"
  };

  /* ---------- Complete IANA Timezone -> ISO Country Map ---------- */
  const TZ_CC = {"Africa/Abidjan":"CI","Africa/Accra":"GH","Africa/Addis_Ababa":"ET","Africa/Algiers":"DZ","Africa/Cairo":"EG","Africa/Casablanca":"MA","Africa/Johannesburg":"ZA","Africa/Lagos":"NG","Africa/Nairobi":"KE","Africa/Tunis":"TN","America/Anchorage":"US","America/Argentina/Buenos_Aires":"AR","America/Bogota":"CO","America/Caracas":"VE","America/Chicago":"US","America/Denver":"US","America/Detroit":"US","America/Edmonton":"CA","America/Halifax":"CA","America/Havana":"CU","America/Indiana/Indianapolis":"US","America/Indianapolis":"US","America/Lima":"PE","America/Los_Angeles":"US","America/Manaus":"BR","America/Mexico_City":"MX","America/Monterrey":"MX","America/Montevideo":"UY","America/Montreal":"CA","America/New_York":"US","America/Panama":"PA","America/Phoenix":"US","America/Puerto_Rico":"PR","America/Santiago":"CL","America/Sao_Paulo":"BR","America/St_Johns":"CA","America/Tijuana":"MX","America/Toronto":"CA","America/Vancouver":"CA","America/Winnipeg":"CA","Asia/Almaty":"KZ","Asia/Amman":"JO","Asia/Baghdad":"IQ","Asia/Bahrain":"BH","Asia/Baku":"AZ","Asia/Bangkok":"TH","Asia/Beirut":"LB","Asia/Brunei":"BN","Asia/Calcutta":"IN","Asia/Chongqing":"CN","Asia/Colombo":"LK","Asia/Dhaka":"BD","Asia/Dubai":"AE","Asia/Harbin":"CN","Asia/Ho_Chi_Minh":"VN","Asia/Hong_Kong":"HK","Asia/Irkutsk":"RU","Asia/Istanbul":"TR","Asia/Jakarta":"ID","Asia/Jerusalem":"IL","Asia/Kabul":"AF","Asia/Kamchatka":"RU","Asia/Karachi":"PK","Asia/Kashgar":"CN","Asia/Kathmandu":"NP","Asia/Kolkata":"IN","Asia/Krasnoyarsk":"RU","Asia/Kuala_Lumpur":"MY","Asia/Kuwait":"KW","Asia/Macao":"MO","Asia/Macau":"MO","Asia/Makassar":"ID","Asia/Manila":"PH","Asia/Muscat":"OM","Asia/Nicosia":"CY","Asia/Novosibirsk":"RU","Asia/Omsk":"RU","Asia/Phnom_Penh":"KH","Asia/Qatar":"QA","Asia/Rangoon":"MM","Asia/Riyadh":"SA","Asia/Saigon":"VN","Asia/Sakhalin":"RU","Asia/Samarkand":"UZ","Asia/Seoul":"KR","Asia/Shanghai":"CN","Asia/Singapore":"SG","Asia/Taipei":"TW","Asia/Tashkent":"UZ","Asia/Tbilisi":"GE","Asia/Tehran":"IR","Asia/Tel_Aviv":"IL","Asia/Tokyo":"JP","Asia/Ulaanbaatar":"MN","Asia/Urumqi":"CN","Asia/Vientiane":"LA","Asia/Vladivostok":"RU","Asia/Yakutsk":"RU","Asia/Yangon":"MM","Asia/Yekaterinburg":"RU","Asia/Yerevan":"AM","Atlantic/Azores":"PT","Atlantic/Reykjavik":"IS","Australia/Adelaide":"AU","Australia/Brisbane":"AU","Australia/Darwin":"AU","Australia/Hobart":"AU","Australia/Melbourne":"AU","Australia/Perth":"AU","Australia/Sydney":"AU","Europe/Amsterdam":"NL","Europe/Athens":"GR","Europe/Belgrade":"RS","Europe/Berlin":"DE","Europe/Bratislava":"SK","Europe/Brussels":"BE","Europe/Bucharest":"RO","Europe/Budapest":"HU","Europe/Chisinau":"MD","Europe/Copenhagen":"DK","Europe/Dublin":"IE","Europe/Helsinki":"FI","Europe/Istanbul":"TR","Europe/Kaliningrad":"RU","Europe/Kiev":"UA","Europe/Kyiv":"UA","Europe/Lisbon":"PT","Europe/Ljubljana":"SI","Europe/London":"GB","Europe/Luxembourg":"LU","Europe/Madrid":"ES","Europe/Malta":"MT","Europe/Minsk":"BY","Europe/Monaco":"MC","Europe/Moscow":"RU","Europe/Oslo":"NO","Europe/Paris":"FR","Europe/Prague":"CZ","Europe/Riga":"LV","Europe/Rome":"IT","Europe/Samara":"RU","Europe/Sofia":"BG","Europe/Stockholm":"SE","Europe/Tallinn":"EE","Europe/Vienna":"AT","Europe/Vilnius":"LT","Europe/Warsaw":"PL","Europe/Zagreb":"HR","Europe/Zurich":"CH","Pacific/Auckland":"NZ","Pacific/Fiji":"FJ","Pacific/Guam":"GU","Pacific/Honolulu":"US","PRC":"CN","ROC":"TW","ROK":"KR","Hongkong":"HK","Singapore":"SG","Japan":"JP","US/Pacific":"US","US/Eastern":"US","US/Central":"US","US/Mountain":"US"};

  const LANG_CC = {
    ja: "JP", ko: "KR", de: "DE", fr: "FR", it: "IT", ru: "RU", uk: "UA", pl: "PL", nl: "NL",
    tr: "TR", vi: "VN", th: "TH", id: "ID", ms: "MY", he: "IL", fa: "IR", el: "GR", cs: "CZ",
    sk: "SK", hu: "HU", ro: "RO", bg: "BG", sv: "SE", da: "DK", nb: "NO", no: "NO", fi: "FI",
    hi: "IN", bn: "BD", ur: "PK", km: "KH", my: "MM", mn: "MN", fil: "PH", tl: "PH"
  };
  const SPOKEN = {
    zh: ["CN", "SG", "MY"],
    "zh-Hant": ["TW", "HK", "MO"],
    es: ["ES", "MX", "AR", "CO", "CL", "PE", "VE", "US"],
    pt: ["PT", "BR"],
    fr: ["FR", "BE", "CH", "CA", "LU"],
    de: ["DE", "AT", "CH", "LU"],
    it: ["IT", "CH"],
    nl: ["NL", "BE"],
    ru: ["RU", "BY", "KZ", "UA"],
    ar: ["SA", "AE", "EG", "QA", "KW", "MA"],
    ms: ["MY", "SG", "BN"],
    ko: ["KR"],
    ja: ["JP"]
  };

  let REG_ZH = null, LNG_ZH = null, REG_EN = null;
  try { REG_ZH = new Intl.DisplayNames(["zh-CN"], { type: "region" }); } catch (e) {}
  try { LNG_ZH = new Intl.DisplayNames(["zh-CN"], { type: "language" }); } catch (e) {}
  try { REG_EN = new Intl.DisplayNames(["en"], { type: "region" }); } catch (e) {}

  function countryName(cc) {
    if (!cc) return "未知地区";
    const u = String(cc).toUpperCase();
    if (u === "TW") return "中国台湾";
    if (u === "HK") return "中国香港";
    if (u === "MO") return "中国澳门";
    try { return (REG_ZH && REG_ZH.of(u)) || u; } catch (e) { return u; }
  }
  function flagEmoji(cc) {
    if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return "🌐";
    const u = cc.toUpperCase() === "TW" ? "CN" : cc.toUpperCase();
    return String.fromCodePoint(0x1F1E6 + u.charCodeAt(0) - 65, 0x1F1E6 + u.charCodeAt(1) - 65);
  }
  function languageName(tag) {
    if (!tag) return "未知语言";
    let s = tag;
    try { s = (LNG_ZH && LNG_ZH.of(tag)) || tag; } catch (e) {}
    if (/-TW\b/i.test(tag)) s = "繁体中文（中国台湾）";
    return s;
  }
  function tzCC(tz) { return TZ_CC[tz] || null; }
  function langCC(tag) {
    if (!tag) return null;
    const p = String(tag).split(/[-_]/), base = p[0].toLowerCase();
    const reg = p.slice(1).find(x => /^[A-Za-z]{2}$/.test(x));
    if (reg) return reg.toUpperCase();
    if (base === "zh") return /hant/i.test(tag) ? "TW" : "CN";
    return LANG_CC[base] || null;
  }
  function spokenIn(tag) {
    if (!tag) return [];
    const base = String(tag).split(/[-_]/)[0].toLowerCase();
    const key = base === "zh" && /hant|-(tw|hk|mo)\b/i.test(tag) ? "zh-Hant" : base;
    const own = langCC(tag);
    return Array.from(new Set([...(own ? [own] : []), ...(SPOKEN[key] || [])]));
  }
  function sameLanguageCountries(cc) {
    const out = new Set([cc]);
    for (const [k, list] of Object.entries(SPOKEN)) {
      if (list[0] === cc) for (const c of spokenIn(k === "zh-Hant" ? "zh-TW" : k)) out.add(c);
    }
    return Array.from(out);
  }

  async function sha256(str) {
    try {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(str)));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    } catch (e) {
      let h = 0x811c9dc5;
      const s = String(str);
      for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
      return (h >>> 0).toString(16).padStart(8, "0").repeat(4);
    }
  }
  const shortHash = h => h ? `${h.slice(0, 8)}·${h.slice(8, 16)}` : "–";

  const getJSON = (url, ms = 5500, creds = "omit") =>
    fetch(url, { cache: "no-store", credentials: creds, signal: AbortSignal.timeout(ms) }).then(r => r.ok ? r.json() : Promise.reject(new Error(r.status)));
  const getText = (url, ms = 5500) =>
    fetch(url, { cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(ms) }).then(r => r.ok ? r.text() : Promise.reject(new Error(r.status)));

  /* ---------- 8 Groups & 148 Genuine Probes Catalog ---------- */
  const GROUPS = [
    ["net", "服务端与协议栈透视", "由服务端网卡 AF_PACKET 旁路抓包、主动 :443 反向握手与微脉冲时序直接读取，JS 插件无法伪造"],
    ["rep", "出口信誉、BGP 路由与黑名单情报", "融合 8 源欺诈库加权几率投票、RDAP 租赁/广播核验、12 项 DNSBL、15 项威胁段与同 /24 脏邻居连坐"],
    ["exit", "多路由分流与双栈矩阵", "并发探测国内外、AI 平台与 IPv4/IPv6 双栈出口，抓捕规则分流漏底"],
    ["hdr", "HTTP 原始请求头与高熵提示", "浏览器建立连接时发往服务端的原始 HTTP 头与 Client Hints"],
    ["loc", "语言、时区与输入法区域", "跨层比对语言列表、IANA 时区、ICU 字典排序规则、键盘键位与内置离线语音"],
    ["dev", "硬件规格、图形栈与光栅化", "物理屏幕反算、WASM 虚拟化抖动、原生控件几何、跨系统字体光栅化与内核真实版本"],
    ["brw", "浏览器偏好、扩展与反篡改", "广告拦截实测、36 款 Chrome 扩展资源扫描、Worker/iframe 与 52 项原型谎言检测"],
    ["fp", "跨站指纹与无痕留痕追踪", "综合指纹、跨浏览器物理硬件码、无状态 ETag 缓存追踪与亚像素渲染哈希"]
  ];

  // [id, group, title, maskSensitive, whyDesc] — Exactly 148 probes
  const SNIFFERS = [
    // Group 1: net (29)
    ["ip", "net", "当前连接出口 IP", true, "服务端 TCP Socket 与反向代理直接看到的客户端公网地址及 IP 协议版本。"],
    ["geo", "net", "出口地理位置（按 IP 库估）", true, "基于双源 IP 库反查的国家、省份/州与城市（仅代表出口网关位置，非 GPS 定位）。"],
    ["coords", "net", "出口经纬度坐标", true, "出口 IP 登记网关的大致经纬度坐标，可与下方手动 GPS 定位测算物理偏差。"],
    ["isp", "net", "自治系统号 (ASN) 与运营商", true, "出口 IP 所属的自治系统编号与网络运营机构名称。"],
    ["nettype", "net", "线路属性判定", false, "综合 ASN 名单、机房关键字、蜂窝标志与 Apple Relay 网段识别机房 VPS 或原生家宽。"],
    ["tzip", "net", "出口 IP 所属时区", false, "出口 IP 所在地理区域对应的标准 IANA 时区与当前 UTC 偏移量。"],
    ["ptr", "net", "反向 DNS 解析 (PTR)", true, "对出口 IP 进行反向域名解析得到的主机名，家宽常含 dynamic/broadband，机房常含 cloud/vps。"],
    ["tcprtt", "net", "服务端 TCP 握手 vs 浏览器 RTT", false, "服务端旁路抓包实测 SYN→ClientHello 物理握手延迟，与浏览器 HTTP 往返对比可抓出代理中转多绕的路程。"],
    ["muxjitter", "net", "微脉冲粘包与多路复用抖动", false, "连续发射微间隔并发 HTTP 脉冲，对比服务端微秒级到达间隔压缩比与 RTT 抖动标准差，识别 smux/yamux/h2mux 隧道合并特征。"],
    ["clock", "net", "本机时钟与服务端偏差", false, "利用往返中点校准法测量浏览器系统时间与服务端标准时间的快慢误差。"],
    ["proto", "net", "HTTP 与 TLS 协商套件", false, "当前页面连接实际协商的 HTTP 版本、TLS 协议版本与对称加密套件。"],
    ["tcpfp", "net", "TCP SYN 被动协议栈系统", false, "服务端直接抓包读取首个 TCP SYN 包的初始 TTL（Windows=128，macOS/Linux=64）、跳数与选项排列推断真实发包内核。"],
    ["ipquirk", "net", "IP 层 DF/IPID/ECN 与内核时钟", false, "深度解析 IPv4 DF 不分片位、SYN→Hello IPID 步进策略、ECN 拥塞标记与 TCP TSval 时间戳频率（Hz），专抓无状态 NFQUEUE 改包伪造。"],
    ["ja4t", "net", "TCP 窗口、MSS 与 JA4T 指纹", false, "由 TCP 初始接收窗口、选项序列编码、MSS 与窗口缩放因子组成的传输层指纹 JA4T。"],
    ["tunnel", "net", "链路 MTU 与 VPN 隧道特征", false, "由 TCP MSS 反推路径 MTU：1500 为标准以太网，1492 为 PPPoE，1420/1280 常为 WireGuard/TUN 隧道，>1500 为云内网巨型帧。"],
    ["ja4", "net", "TLS ClientHello 指纹 (JA4)", false, "从原始 TLS 握手首包提取加密套件、扩展与签名算法计算的行业标准 JA4 指纹。"],
    ["ja3", "net", "TLS JA3 哈希与 GREASE", false, "经典 MD5 格式 JA3 TLS 指纹，以及是否包含浏览器特有的 RFC 8701 GREASE 随机注入值。"],
    ["tlsext", "net", "TLS 浏览器专属扩展特征", false, "检查 ALPS 应用层设置扩展与 Brotli 证书压缩扩展，真浏览器具备而 curl/Go/Python 脚本通常缺失。"],
    ["pqkex", "net", "后量子密钥交换 (PQ-KEM)", false, "检查 TLS ClientHello KeyShare 是否启用抗量子计算破解的 X25519MLKEM768 混合密钥交换。"],
    ["ech", "net", "加密 ClientHello (ECH)", false, "检查 TLS 握手是否携带 0xfe0d ECH 扩展以加密保护目标域名 SNI。"],
    ["reality443", "net", "出口 :443 反向握手与 Reality 验真", false, "主动回探出口公网 IP 的 443 端口：若非微软/苹果/雅虎等大厂 ASN 却返回其有效证书或通过严格 SNI 签名校验，即可实锤 VLESS-Reality / ShadowTLS 偷证书伪装。"],
    ["h2fp", "net", "HTTP 请求头序签名", false, "不同浏览器内核发送请求头的先后顺序各自固定，改 UA 插件无法改变底层发包头顺序。"],
    ["quicfp", "net", "HTTP/3 (QUIC / UDP 443) 探测", false, "结合边缘协商与 ResourceTiming 检测当前网络及代理链路是否放行基于 UDP 443 的 QUIC 协议。"],
    ["dns", "net", "递归 DNS 解析器出口", true, "生成随机一次性子域名触发真实递归查询，定位替你解析域名的上游 DNS 服务器国家与运营商。"],
    ["ecs", "net", "多路递归 DNS 集群与 ECS 归属", true, "并发探测上游 DNS 集群节点并核验 EDNS Client Subnet (ECS) 子网透传及运营商同源性（本网 ISP / 公共 Anycast / 跨境泄漏）。"],
    ["webrtc", "net", "WebRTC STUN 公网地址", true, "通过 STUN 协议在 UDP 通道探测本机反射出的真实公网 IPv4/IPv6 地址，未开 TUN 的代理常在此漏底。"],
    ["udprtt", "net", "WebRTC UDP 握手 vs TCP 往返差", false, "对比浏览器直接发起的 STUN UDP 候选返回耗时与 HTTP TCP 热连接往返耗时，识别仅代理 TCP 或高开销 UDP-over-TCP 封装。"],
    ["lan", "net", "WebRTC 局域网地址与 mDNS", true, "读取 ICE Host 候选：现代浏览器通常用随机 .local (mDNS) 隐藏内网 IP，旧环境或特殊设置会直接暴露。"],
    ["v6mac", "net", "IPv6 物理网卡 MAC 泄露", true, "扫描所有观测到的 IPv6 地址后 64 位是否含 ff:fe (EUI-64)，一旦命中即永久暴露物理网卡 MAC。"],

    // Group 2: rep (11) — Multi-Source Egress Reputation, BGP/RDAP & Dirty Neighbours
    ["rep_score", "rep", "出口 IP 纯净度评分与加扣分账单", false, "基准 92 分 + 最高 10 分原生安全奖励 − 五维封顶扣分（匿名化/黑名单/同段邻居/机房租赁/广播分歧），输出 S~F 纯净度等级。"],
    ["rep_votes", "rep", "8 源欺诈库加权几率投票", false, "融合 ipapi.is、IPQuery、IPLocate、Blackbox、ip-api、IPinfo 等最多 8 源做上游去重与加权对数几率融合 E = H/(H+N)。"],
    ["rep_native", "rep", "原生 IP vs 广播 IP 与定位共识", false, "交叉比对 RIR/RDAP 注册国家与多库地理位置共识度，识别跨国 BGP 宣告的「广播 IP」。"],
    ["rep_asn", "rep", "BGP 自治系统画像与自报冲突", false, "结合 PeeringDB 披露的网络类型与流量方向（如 Heavy Outbound）拆穿「自报住宅 ISP、实为机房托管商」的伪家宽。"],
    ["rep_lease", "rep", "IP 地址段租赁 / 转售子分配识别", false, "核查 RDAP 分配备注与子分配年代，识别经由 IPXO / InterLIR / Heficed 等经纪平台租借拼装的商业网段。"],
    ["rep_rpki", "rep", "BGP 宣告规模、RPKI 签名与注册年限", false, "统计所属 ASN 全球路由前缀数、IPv4 地址池规模、RPKI ROA 路由源密码学验签状态与机构注册年份。"],
    ["rep_shodan", "rep", "Shodan InternetDB 开放端口与漏洞", false, "查询该出口公网 IP 被全球扫描器记录的常驻开放端口、代理/云标签、CPE 服务指纹与历史 CVE 漏洞。"],
    ["rep_threat", "rep", "开源威胁情报脉冲 (OTX / SFS / Tor)", false, "联查 AlienVault OTX 攻击脉冲报告、StopForumSpam 垃圾注册举报频次及 Tor Onionoo 出口/中继名录。"],
    ["rep_dnsbl", "rep", "12 项 DoH 实时黑名单与代理特征码", false, "通过加密 DoH 实时核验 Spamhaus ZEN、Barracuda、SpamCop、SORBS 及 DroneBL 开放代理特征码（免疫本地 Fake-IP 污染）。"],
    ["rep_cidr", "rep", "15 项公开威胁网段与 X4BNet 命中", false, "在服务端内存二分检索 FireHOL L1/L2、IPsum ≥3、DShield、ET Compromised 与 X4BNet 机房/VPN 网段集。"],
    ["rep_neigh", "rep", "同 /24 C 段脏邻居与全 ASN 滥用密度", false, "统计同一 /24 网段内其余 255 个邻居近期上榜个数，并按全网路由空间基线折算所属 ASN 每万地址滥用密度倍数。"],

    // Group 3: exit (8)
    ["ex_self", "exit", "本站直连出口（当前节点）", true, "访问当前部署服务器时看到的公网出口 IP 与归属。"],
    ["ex_cn", "exit", "中国大陆网站出口", true, "浏览器直接请求大陆测速节点看到的出口 IP，开启「绕过大陆/规则分流」时会直接暴露国内真实省市与宽带。"],
    ["ex_intl", "exit", "海外通用 IP 服务出口", true, "浏览器请求国际通用 GeoIP 服务时呈现的出口地址与网络机构。"],
    ["ex_gpt", "exit", "OpenAI ChatGPT 出口", true, "请求 chatgpt.com 边缘接口看到的实际分流出口 IP 与机房三字码，识别 AI 专属分流规则。"],
    ["ex_claude", "exit", "Anthropic Claude 出口", true, "请求 claude.ai 边缘接口看到的实际分流出口 IP 与机房节点。"],
    ["ex_cf", "exit", "Cloudflare 全球边缘出口", true, "请求 www.cloudflare.com 看到的出口地址、接入数据中心与协商协议。"],
    ["warp", "exit", "Cloudflare WARP 与 Gateway", false, "检测流量是否经过 Cloudflare WARP 隧道或 Zero Trust Gateway 企业网关。"],
    ["stack", "exit", "IPv4 与 IPv6 双栈独立出口", true, "分别强制通过纯 IPv4 与纯 IPv6 链路探测出口地址，许多代理仅接管 IPv4 而导致 IPv6 直连裸奔。"],

    // Group 4: hdr (9)
    ["h_ua", "hdr", "HTTP User-Agent 请求头", false, "HTTP 请求头中实际携带的 User-Agent 字符串，与 JS navigator.userAgent 对比可抓出浅层改 UA 插件。"],
    ["h_lang", "hdr", "HTTP Accept-Language 头", false, "HTTP 请求头携带的语言权重列表，若与 JS navigator.languages 首项不一致则说明环境被篡改。"],
    ["h_chua", "hdr", "Sec-CH-UA 品牌列表头", false, "Chromium 浏览器在网络层发送的品牌与主版本号 Client Hints。"],
    ["h_plat", "hdr", "Sec-CH-UA-Platform 平台头", false, "网络层上报的操作系统名称、平台真实版本号与移动端标志。"],
    ["h_arch", "hdr", "Sec-CH-UA 架构与位数头", false, "响应服务端 Accept-CH 后浏览器主动上报的 CPU 架构、64/32 位数与硬件型号头。"],
    ["h_enc", "hdr", "Accept-Encoding 压缩支持", false, "客户端支持的响应压缩算法（如 zstd、br、gzip），可辅助识别内核版本与中间层代理修改。"],
    ["h_sec", "hdr", "Sec-Fetch 上下文安全头", false, "现代浏览器自动附加的 Sec-Fetch-Site / Mode / Dest 元数据头。"],
    ["h_dnt", "hdr", "HTTP DNT 与 Sec-GPC 头", false, "网络请求头中携带的请勿追踪 (DNT) 与全球隐私控制 (Sec-GPC) 信号。"],
    ["h_ref", "hdr", "页面来源 Referer", false, "跳转到当前页面时的来源网页地址与导航入口类型。"],

    // Group 5: loc (11)
    ["langs", "loc", "navigator.languages 语言列表", false, "JS 读取的浏览器首选与备选语言全列表，反映用户日常阅读语种。"],
    ["locale", "loc", "Intl 默认区域与历法", false, "国际化引擎默认解析出的区域代码、日历体系与数字书写系统。"],
    ["tz", "loc", "系统 IANA 时区名称", false, "Intl.DateTimeFormat 读取的操作系统时区 ID（如 Asia/Shanghai）及当前标准时间名。"],
    ["tzoff", "loc", "Date 与 Intl 双源时区校验", false, "交叉核对 Date.prototype.getTimezoneOffset() 与 Intl 时区偏移，劣质改时区插件常只改其一。"],
    ["hour", "loc", "默认时钟制式（12/24 小时）", false, "当前语言区域默认采用的小时计数制式及本地格式化时间样本。"],
    ["week", "loc", "每周起始日习惯", false, "Intl.Locale.weekInfo 暴露的一周第一天（如中国/欧洲为周一，美国/日本多为周日）。"],
    ["fmt", "loc", "数字分组与日期格式", false, "本地化长数字千分位小数点样式与年月日排列格式。"],
    ["icu", "loc", "浏览器 ICU 国际化字典规模", false, "统计 Intl.supportedValuesOf 支持的时区、货币、度量单位与历法总数，精简版或旧版内核数量明显不同。"],
    ["intlcoll", "loc", "ICU 默认排序规则与列表语法", false, "测试 Intl.Collator 对汉字拼音/笔画与拉丁变音字符的默认排序顺序及 ListFormat 连接词，识破未改透的区域伪装。"],
    ["kbd", "loc", "物理键盘键位布局", false, "通过 navigator.keyboard.getLayoutMap 静默识别 QWERTY、AZERTY（法语）、QWERTZ（德语）等物理键位。"],
    ["voices", "loc", "系统内置离线朗读语音包", false, "枚举 speechSynthesis 本地语音合成引擎，Windows 系统安装的语言包会在此留下明确语种痕迹。"],

    // Group 6: dev (35)
    ["os", "dev", "真实操作系统与版本", false, "结合高熵 Client Hints 与 Windows 系统专属字体反证（识别伪造 Win11 的旧系统）还原真实 OS 版本。"],
    ["browser", "dev", "浏览器品牌与版本新旧度", false, "解析真实浏览器品牌、主版本号，并推算距离当前最新正式版落后几个版本周期。"],
    ["arch", "dev", "CPU 指令集架构与位数", false, "处理器底层架构（arm / x86）与 64/32 位运行环境。"],
    ["cpu", "dev", "CPU 逻辑核心线程数", false, "navigator.hardwareConcurrency 暴露的处理器逻辑线程数量。"],
    ["cpubench", "dev", "WASM SIMD 指令集与虚拟化抢占抖动", false, "校验真实 WebAssembly 128-bit SIMD 字节码支持度，并采样 60 组微时间片算力延迟比 (p99/p50)，捕捉云服务器/虚拟机 Hypervisor CPU Steal 毛刺。"],
    ["mem", "dev", "物理内存档位 (deviceMemory)", false, "Chromium 浏览器按分档上报的本机物理内存容量下限（最大封顶报 8 GB）。"],
    ["heap", "dev", "V8 单页 JS 堆内存上限", false, "performance.memory.jsHeapSizeLimit 暴露的单标签页最大可用内存（64 位桌面通常约 4.0 GB）。"],
    ["screen", "dev", "屏幕真实物理像素分辨率", false, "结合 CSS 像素与 devicePixelRatio 反算显示器面板原生物理像素（如 Mac Retina 2940×1912）。"],
    ["hz", "dev", "显示器物理刷新率 (Hz)", false, "通过连续 40 帧 requestAnimationFrame 时间间隔中位数实测屏幕真实刷新率（60 / 120 / 144 / 240 Hz）。"],
    ["screens", "dev", "多显示器扩展状态与窗口坐标", false, "screen.isExtended 检测是否连接了多块屏幕，并记录当前窗口在桌面坐标系中的位置。"],
    ["gamut", "dev", "屏幕色域与 HDR 动态范围", false, "CSS 媒体查询探测显示器色彩空间（Display P3 / Rec.2020 / sRGB）与高动态范围 (HDR) 能力。"],
    ["touch", "dev", "触控点数与输入指针类型", false, "最大同时触控点数与主输入设备精度（精细鼠标触控板 vs 粗粒度手指触屏）。"],
    ["uigeom", "dev", "原生表单控件亚像素包围盒几何", false, "测量未加样式的原生 button / select / checkbox / range 控件宽高，macOS Cocoa、Windows Fluent 与 Linux GTK 原生主题尺寸截然不同。"],
    ["fontrast", "dev", "跨系统字体光栅化引擎签名", false, "分析斜线与曲线字形边缘的 RGB 彩边离差与灰阶 Gamma 分布，识破在 Linux/Windows 容器强装苹果 PingFang 字体伪装 Mac 的行为。"],
    ["gpu", "dev", "显卡真实型号与双显卡探测", false, "同时请求默认与 high-performance 上下文，挖掘核显笔记本背后隐藏的独立显卡型号及虚拟机软件渲染特征。"],
    ["glx", "dev", "WebGL 版本与纹理能力上限", false, "WebGL 1/2 支持状态、最大纹理像素尺寸及显卡驱动暴露的扩展总数。"],
    ["webgpu", "dev", "WebGPU 高性能/低功耗双适配器", false, "读取新一代 WebGPU API 的高性能与低功耗双 Adapter 厂商、微架构与设备描述。"],
    ["gpulim", "dev", "WebGPU 硬件 Limits 特征哈希", false, "汇总 GPUAdapter 全部硬件缓冲区/计算管线上限参数与支持特性列表生成的驱动级指纹。"],
    ["audiohw", "dev", "声卡原生采样率与声道数", false, "创建静音 AudioContext 读取声卡硬件默认采样率（如 48 kHz / 44.1 kHz）与最大输出声道。"],
    ["battery", "dev", "电池状态与供电模式", false, "读取电量百分比与充放电状态；满电且充电时间为 0 通常代表外接交流电的台式机或迷你主机。"],
    ["conn", "dev", "浏览器网络链路估算", false, "navigator.connection 上报的有效网络制式、估算 RTT、下行带宽与省流量开关。"],
    ["media", "dev", "免授权音视频外设枚举", false, "无需申请摄像头/麦克风权限即可统计本机连接的摄像头、麦克风与音频输出设备数量。"],
    ["codecs", "dev", "MediaSource 视频编码支持", false, "探测浏览器原生支持的视频编码标准（H.264、VP9、AV1、HEVC/H.265、Dolby Vision、E-AC-3）。"],
    ["hwdec", "dev", "显卡高能效硬件解码格式", false, "通过 mediaCapabilities.decodingInfo 检测哪些高清视频格式由显卡硬件芯片直接硬解。"],
    ["rtccodecs", "dev", "WebRTC 实时音视频编解码器", false, "RTCRtpSender.getCapabilities 暴露的实时通信音视频编码器列表与档位参数。"],
    ["recmime", "dev", "MediaRecorder 录制封装支持", false, "测试浏览器支持录制的 12 种常见音视频容器与编码组合。"],
    ["drm", "dev", "DRM 数字版权管理模块", false, "静默探测 Widevine、FairPlay、PlayReady 与 ClearKey 硬件/软件解密模块支持度。"],
    ["bio", "dev", "平台硬件生物识别认证器", false, "PublicKeyCredential 检测本机是否配备 Touch ID、Face ID 或 Windows Hello 等平台通行密钥硬件。"],
    ["bt", "dev", "蓝牙硬件适配器可用性", false, "navigator.bluetooth.getAvailability 无弹窗检测设备是否存在可用蓝牙模块。"],
    ["storage", "dev", "浏览器磁盘存储配额上限", false, "navigator.storage.estimate 暴露的站点可用磁盘上限，可用于反推磁盘总容量并识别部分无痕模式限制。"],
    ["engine", "dev", "底层 JavaScript 引擎鉴别", false, "利用空对象属性访问抛出的原生异常措辞差异，不可伪造地区分 V8、SpiderMonkey 与 JavaScriptCore。"],
    ["engver", "dev", "JS 语法特性反推真实内核版本", false, "逐一测试 Chromium 97–136+ 各版本引入的原生 JS API，直接拆穿指纹浏览器虚报高版本 UA 的行为。"],
    ["cssv", "dev", "CSS 特性反推渲染引擎版本", false, "测试 :has()、color-mix()、anchor-name、reading-flow 等现代 CSS 特性，锁定真实 Blink 内核代际。"],
    ["apis", "dev", "硬件敏感接口暴露面", false, "统计 WebUSB、WebHID、WebSerial、MIDI、NFC、本地字体访问等 12 项硬件 API 是否存在。"],
    ["emoji", "dev", "系统字库 Emoji 版本代际", false, "利用 Canvas 测量 Emoji 12.0 至 16.0 新字符渲染宽度，反推操作系统内置字体新旧程度。"],

    // Group 7: brw (22)
    ["scheme", "brw", "系统深浅色与对比度偏好", false, "读取 prefers-color-scheme 系统外观主题与高对比度模式。"],
    ["sysui", "brw", "默认字号与系统强调色", false, "读取浏览器基础字号（默认 16px）及操作系统级 AccentColor 强调色值。"],
    ["scrollbar", "brw", "原生滚动条物理宽度", false, "测量系统滚动条占用像素：macOS/移动端通常为 0px 悬浮滚动条，Windows 经典模式为 15–17px。"],
    ["smooth", "brw", "系统字体抗锯齿渲染模式", false, "分析 Canvas 文字边缘像素是否存在 RGB 彩边，区分 Windows ClearType 子像素渲染与 macOS 灰度平滑。"],
    ["motion", "brw", "减弱动态效果设置", false, "读取系统辅助功能中的 prefers-reduced-motion 动画减弱开关。"],
    ["a11y", "brw", "无障碍与视觉辅助偏好", false, "检测高对比度、强制色彩、减少透明度、反色模式与省流偏好。"],
    ["display", "brw", "窗口运行容器形态", false, "区分普通浏览器标签页、全屏模式、已安装的 PWA 独立窗口或社交 App 内置 WebView。"],
    ["win", "brw", "视口尺寸与系统栏占用高度", false, "读取当前网页可视窗口尺寸，并由屏幕总高度减去可用高度推算 Dock / 任务栏占用像素。"],
    ["dnt", "brw", "JS 隐私声明信号 (DNT/GPC)", false, "读取 navigator.doNotTrack 与 navigator.globalPrivacyControl 客户端状态。"],
    ["cookies", "brw", "Cookie 读写启用状态", false, "检测当前上下文是否允许读写 Cookie。"],
    ["pdf", "brw", "内置 PDF 阅读器支持", false, "navigator.pdfViewerEnabled 状态，无头爬虫或精简容器偶有差异。"],
    ["perms", "brw", "核心权限静默状态查询", false, "通过 Permissions API 不弹窗查询定位、通知、摄像头、麦克风当前授权态。"],
    ["history", "brw", "当前标签页会话栈深度", false, "history.length 反映当前标签页已连续浏览的页面数量（自动化脚本通常恒为 1 或 2）。"],
    ["webdriver", "brw", "自动化框架与驱动痕迹", false, "综合检测 navigator.webdriver、Selenium/CDC、Playwright 与 Puppeteer 注入钩子。"],
    ["adblock", "brw", "广告拦截插件双重实测", false, "结合页面多类名广告 DOM 诱饵隐藏检测与 Google 广告脚本网络请求拦截对照（排除断网误判）。"],
    ["ext", "brw", "页面注入痕迹识别扩展", false, "检测加密钱包全局对象（MetaMask/OKX/Phantom/Rabby）、DevTools 钩子与翻译/暗色插件 DOM 标记。"],
    ["extwar", "brw", "Chrome 扩展公开资源扫描", false, "并发探测 36 款主流代理、改指纹、脚本管理器、钱包与密码管理扩展暴露的 chrome-extension:// 静态资源。"],
    ["worker", "brw", "Web Worker 线程交叉核验", false, "启动独立 Worker 线程读取 navigator 与时区，与主线程逐项对比，专抓只改主页面的防关联插件。"],
    ["iframe", "brw", "洁净 iframe 沙箱交叉核验", false, "动态创建空白同源 iframe 对照 navigator、screen 与时区读数，识别页面级浅层注入。"],
    ["lies", "brw", "52 项原生接口谎言检测", false, "利用洁净 iframe 的 Function.toString、prototype 属性检查与非法调用异常测试，抓捕被重写过的原生 API。"],
    ["shield", "brw", "防指纹护盾品牌归因", false, "根据加噪方式与特征识别 Brave Farbling、Firefox RFP、Safari 高级防追踪或第三方改指纹扩展。"],
    ["trackers", "brw", "7 大追踪器拦截实测（手动）", false, "点击按钮后向 Google Analytics、DoubleClick、Meta、Bing、TikTok、百度统计、Hotjar 发起无 Cookie 测试请求。"],

    // Group 8: fp (23)
    ["fpid", "fp", "跨站综合浏览器指纹 ID", false, "汇总 Canvas、WebGL、音频、字体、屏幕、时区与硬件参数生成的与 IP 无关的跨站追踪 ID。"],
    ["hwid", "fp", "跨浏览器物理硬件编号", false, "仅选取由电脑硬件与操作系统决定的特征（物理屏幕、核数、显卡、时区、字库）计算，换浏览器访问仍高度一致。"],
    ["etag", "fp", "HTTP ETag 缓存追踪编号", false, "零服务端数据库存储：利用浏览器 If-None-Match 缓存协商机制，即使清空 Cookie 与本地存储仍能认出回访者。"],
    ["traces", "fp", "4 大浏览器存储留痕测试", false, "在 LocalStorage、IndexedDB、Cache Storage 与 window.name 写入本地随机标记，检验清理不彻底时的身份复活。"],
    ["canvas", "fp", "Canvas 2D 绘图指纹哈希", false, "绘制渐变、混排中英文 Emoji 与抗锯齿圆弧，提取底层图形光栅化差异哈希。"],
    ["rand", "fp", "Canvas 双次重绘随机化", false, "同一页面连续绘制两次完全相同的画布并比对输出，判断是否存在每次调用随机加噪。"],
    ["pxnoise", "fp", "16×16 棋盘格隐蔽加噪检测", false, "绘制已知精确 RGB 值的双色块与单像素棋盘格回读像素，专抓只篡改边缘异色像素的隐蔽防指纹插件。"],
    ["webgl", "fp", "WebGL 驱动参数与扩展哈希", false, "汇总显卡渲染器、着色器精度、最大视口/纹理/向量上限及扩展列表生成的哈希。"],
    ["glimg", "fp", "WebGL 着色器像素回读指纹", false, "使用自定义片元着色器渲染正余弦渐变三角形并逐像素 readPixels 回读，捕捉 GPU 浮点舍入差异。"],
    ["audio", "fp", "OfflineAudio 音频压缩指纹", false, "离线渲染 10kHz 三角波经动态压缩器处理后的采样幅值总和，不同音频栈与架构存在细微差异。"],
    ["aunoise", "fp", "ConstantSource 音频加噪检测", false, "离线渲染恒定 0.5 幅值直流音频源并回读全部采样，任何偏离 0.5 的微小抖动均证明存在防指纹音频篡改。"],
    ["fonts", "fp", "已安装代表性字体清单", false, "通过 Canvas 72px 多族基线宽度比对，无弹窗检测 52 款中英日韩、编程、Adobe 设计与 Office 字体。"],
    ["fontfp", "fp", "字体集合哈希与软件画像", false, "根据本机已安装字体组合计算唯一哈希，并推断开发、设计或商务办公软件环境。"],
    ["domrect", "fp", "DOMRect 旋转排版亚像素指纹", false, "对旋转倾斜文字块调用 getClientRects 与 Range.getBoundingClientRect，提取小数点后 6 位排版特征。"],
    ["svgrect", "fp", "SVG 文字度量几何指纹", false, "读取 SVG text 元素的 getBBox、getComputedTextLength 与子串长度亚像素指纹。"],
    ["textm", "fp", "Canvas 多字体包围盒度量", false, "测量 serif/sans-serif/monospace/cursive 四种字体上下左右实际渲染边界 (actualBoundingBox)。"],
    ["mathfp", "fp", "CPU / 引擎超越函数数学指纹", false, "计算 12 组极端入参三角/双曲/指数对数函数结果，反映底层数学库（fdlibm/CRT）实现差异。"],
    ["keys", "fp", "引擎全局对象属性计数", false, "统计 window、HTMLElement.prototype 与 CSSStyleDeclaration 属性总数，随浏览器小版本递增而变化。"],
    ["timer", "fp", "高精度计时器最小步长", false, "实测 performance.now() 最小可分辨时间粒度，识别防指纹模式故意调粗时钟（如 ≥10ms）的行为。"],
    ["callstack", "fp", "JS 同步递归调用栈深度", false, "探测引擎触发栈溢出前的最大自调用层数，与引擎版本及线程栈大小绑定。"],
    ["perf_nav", "fp", "导航与连接时序特征", false, "读取 PerformanceNavigationTiming 中的协议、TLS 建连与首字节响应耗时特征。"],
    ["geoloc", "fp", "硬件精确定位偏差（需授权）", true, "仅在手动点击时调用浏览器定位权限，纯本地计算 GPS/Wi-Fi 坐标与当前出口 IP 估算位置的直线距离。"],
    ["sensors", "fp", "陀螺仪与加速度计噪声（需授权）", false, "移动端手动点击采集 1.5 秒运动传感器采样频率与零偏标准差硬件指纹，纯本地计算不上传。"]
  ];

  // 20 Core Disguise, Deep Stack & Reputation Checks + 4 Protocol Security Checks = 24 Checks
  const CORE_CHECKS = [
    ["tz", "时区与出口 IP 对齐", ["disguise"]],
    ["lang", "浏览器语言与出口对齐", ["disguise"]],
    ["syslang", "系统底层语种（字库/语音/键位）", ["disguise"]],
    ["dns", "DNS 解析器与 ECS 子网泄漏", ["disguise", "privacy"]],
    ["split", "国内外与 AI 多路分流一致性", ["disguise"]],
    ["conn", "底层 TCP/TLS 协议栈与自报系统", ["disguise"]],
    ["synspoof", "IP/TCP 内核时钟连续性与防改包", ["disguise"]],
    ["reality", "出口 :443 反向验真与 Reality 偷证书", ["disguise"]],
    ["rtt", "往返延迟三维测距（TCP/HTTP/UDP）", ["disguise"]],
    ["webrtc", "WebRTC STUN 真实 IP 与网卡 MAC 泄漏", ["disguise", "privacy"]],
    ["dc", "出口 IP 机房 / 原生住宅多源投票", ["disguise"]],
    ["lease", "伪家宽自报冲突、IP 租赁段与广播属性", ["disguise"]],
    ["reputation", "欺诈风险、黑名单与同 /24 脏邻居连坐", ["disguise"]],
    ["subpixel", "字体光栅化、原生控件与滚动条跨系统核验", ["disguise"]],
    ["hwvirt", "虚拟化抢占抖动与显卡硬解芯片核验", ["disguise"]],
    ["tamper", "浏览器环境篡改与谎言检测", ["disguise"]],
    ["fpb", "指纹浏览器与跨线程矛盾", ["disguise"]],
    ["ua", "UA、Client Hints 与显卡系统一致性", ["disguise"]],
    ["bot", "自动化控制与无头浏览器痕迹", ["disguise"]],
    ["fp", "跨站指纹与无痕缓存追踪抗性", ["privacy"]]
  ];

  const PROTO_CHECKS = [
    ["pq", "后量子混合密钥交换 (PQ-KEM)"],
    ["ech", "加密 ClientHello (ECH 域名保护)"],
    ["h3", "HTTP/3 (QUIC / UDP 443 连通性)"],
    ["warp", "Cloudflare WARP / Gateway 隧道"]
  ];

  /* ---------- Pure Inference Helpers ---------- */
  function tzOffsetMin(tz) {
    try {
      const p = new Intl.DateTimeFormat("en-US", { timeZone: tz, timeZoneName: "longOffset" })
        .formatToParts(new Date()).find(x => x.type === "timeZoneName")?.value || "";
      const m = p.match(/GMT([+-−])(\d{2}):?(\d{2})?/);
      return m ? (m[1] === "+" ? 1 : -1) * (+m[2] * 60 + +(m[3] || 0)) : 0;
    } catch (e) { return null; }
  }
  function fmtUtcOffset(min) {
    if (min == null) return "";
    return (min < 0 ? "−" : "+") + String(Math.floor(Math.abs(min) / 60)).padStart(2, "0") + ":" + String(Math.abs(min) % 60).padStart(2, "0");
  }
  function tzGenericLabel(tz) {
    try {
      return new Intl.DateTimeFormat("zh-CN", { timeZone: tz, timeZoneName: "longGeneric" })
        .formatToParts(new Date()).find(x => x.type === "timeZoneName")?.value || tz;
    } catch (e) { return tz || "未知时区"; }
  }

  function detectDevice(ua = "", hi = {}, touch = 0) {
    let os = null, osv = "", kind = "pc", model = hi.model || "";
    const plat = hi.platform || "", pv = hi.platformVersion || "";
    if (/^(HarmonyOS|OpenHarmony)$/i.test(plat) || /OpenHarmony|HarmonyOS|ArkWeb/.test(ua)) {
      os = "HarmonyOS";
      const v = ua.match(/(?:OpenHarmony|HarmonyOS)[ /]?(\d+(?:\.\d+)?)/);
      osv = pv ? pv.split(".").slice(0, 2).join(".").replace(/\.0$/, "") : v ? v[1] : "";
      kind = /Mobile|\(Phone;/i.test(ua) || hi.mobile ? "phone" : touch > 1 ? "tablet" : "pc";
    } else if (plat === "Windows" || /Windows NT/.test(ua)) {
      os = "Windows";
      if (pv) osv = parseInt(pv, 10) >= 13 ? "11" : parseInt(pv, 10) > 0 ? "10" : "";
      else {
        const m = ua.match(/Windows NT ([\d.]+)/);
        osv = m ? ({ "10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7" })[m[1]] || m[1] : "";
      }
    } else if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && touch > 1)) {
      const ipad = /iPad/.test(ua) || /Macintosh/.test(ua);
      os = ipad ? "iPadOS" : "iOS";
      kind = ipad ? "tablet" : "phone";
      const m = ua.match(/OS (\d+)[_.](\d+)/) || ua.match(/Version\/(\d+)\.(\d+)/);
      osv = m ? `${m[1]}.${m[2]}` : "";
      model = ipad ? "iPad" : "iPhone";
    } else if (plat === "macOS" || /Macintosh|Mac OS X/.test(ua)) {
      os = "macOS";
      kind = "mac";
      if (pv) osv = pv.split(".").slice(0, 2).join(".").replace(/\.0$/, "");
      else {
        const m = ua.match(/Mac OS X (\d+)[_.](\d+)/);
        osv = m ? `${m[1]}.${m[2]}` : "";
      }
    } else if (plat === "Android" || /Android/.test(ua)) {
      os = "Android";
      kind = /Mobile/.test(ua) || hi.mobile ? "phone" : "tablet";
      osv = pv ? pv.split(".")[0] : ((ua.match(/Android (\d+)/) || [])[1] || "");
      if (!model) {
        const m = ua.match(/Android [\d.]+; ([^;)]+?)(?: Build|\))/);
        if (m && m[1] !== "K") model = m[1].trim();
      }
    } else if (plat === "Chrome OS" || /CrOS/.test(ua)) {
      os = "ChromeOS";
    } else if (plat === "Linux" || /Linux/.test(ua)) {
      os = "Linux";
    }
    return { os, osv, kind, model };
  }

  const IN_APPS = [
    ["WeChat", /MicroMessenger\/(\d+)/],
    ["Telegram", /Telegram-Android\/(\d+)|Telegram/i],
    ["X", /Twitter for (?:iPhone|iPad|Android)\/(\d+)|TwitterAndroid\/(\d+)/],
    ["Weibo", /Weibo \(|__weibo__(\d+)/],
    ["QQ", /\bQQ\/(\d+)/],
    ["TikTok", /musical_ly_(\d+)|BytedanceWebview|TikTok (\d+)/],
    ["Instagram", /Instagram (\d+)/],
    ["Facebook", /FBAV\/(\d+)|\[FBAN/]
  ];
  function detectBrowser(ua = "", brands = []) {
    for (const [name, re] of IN_APPS) {
      const m = ua.match(re);
      if (m) return { name, v: (m.slice(1).find(Boolean) || "").split(".")[0], inApp: true };
    }
    const real = (brands || []).filter(b => !/Not.?A.?Brand|Chromium/i.test(b.brand || ""));
    const pick = real.find(b => !/Google Chrome/.test(b.brand || "")) || real[0];
    if (pick) {
      return {
        name: String(pick.brand).replace(/^Microsoft /, "").replace(/^Google /, ""),
        v: String(pick.version || "").split(".")[0],
        inApp: false
      };
    }
    const rules = [
      ["Edge", /Edg(?:e|A|iOS)?\/(\d+)/],
      ["Opera", /OPR\/(\d+)/],
      ["Brave", /Brave\/(\d+)/],
      ["Vivaldi", /Vivaldi\/(\d+)/],
      ["Samsung Internet", /SamsungBrowser\/(\d+)/],
      ["Firefox", /(?:Firefox|FxiOS)\/(\d+)/],
      ["Chrome", /(?:Chrome|CriOS)\/(\d+)/],
      ["Safari", /Version\/(\d+).*Safari/]
    ];
    for (const [name, re] of rules) {
      const m = ua.match(re);
      if (m) return { name, v: m[1], inApp: /; wv\)/.test(ua) };
    }
    return { name: null, v: "", inApp: /; wv\)/.test(ua) };
  }

  const STD_SIZES = [
    [7680, 4320], [6016, 3384], [5120, 2880], [5120, 2160], [5120, 1440], [4096, 2304],
    [3840, 2400], [3840, 2160], [3840, 1600], [3456, 2234], [3440, 1440], [3200, 1800],
    [3024, 1964], [3000, 2000], [2940, 1912], [2880, 1864], [2880, 1800], [2736, 1824],
    [2560, 1664], [2560, 1600], [2560, 1440], [2560, 1080], [2256, 1504], [2160, 1440],
    [1920, 1200], [1920, 1080], [1680, 1050], [1600, 900], [1440, 900], [1366, 768], [1280, 800], [1280, 720]
  ];
  function calcPhysicalScreen(w, h, dpr = 1) {
    const near = (x, y) => STD_SIZES.find(([a, b]) =>
      (Math.abs(a - x) <= a * 0.01 && Math.abs(b - y) <= b * 0.01) ||
      (Math.abs(a - y) <= a * 0.01 && Math.abs(b - x) <= b * 0.01)
    );
    const pw = Math.round(w * dpr), ph = Math.round(h * dpr);
    const hit = near(pw, ph);
    if (hit) return (w >= h) === (hit[0] >= hit[1]) ? [hit[0], hit[1]] : [hit[1], hit[0]];
    if (dpr > 1 && Number.isInteger(dpr)) return [pw, ph];
    const scales = [1, 1.25, 1.5, 1.75, 2, 2.25, 2.5, 3];
    const ordered = [...scales.filter(s => s < dpr).reverse(), ...scales.filter(s => s > dpr)];
    for (const s of ordered) {
      const m = near(Math.round(w * s), Math.round(h * s));
      if (m) return (w >= h) === (m[0] >= m[1]) ? [m[0], m[1]] : [m[1], m[0]];
    }
    return [pw, ph];
  }

  function cleanGpuName(raw) {
    if (!raw || /^(Brave|Mozilla|Generic Renderer)$/i.test(raw)) return null;
    let s = String(raw).replace(/,? or similar$/, "");
    const m = s.match(/^ANGLE \((?:[^,]*), (.*?)(?:, [^,]*)?\)$/);
    if (m) s = m[1].replace(/^ANGLE Metal Renderer: /, "");
    s = s.replace(/\s*\(0x[0-9a-f]+\)/i, "")
         .replace(/\s+(Direct3D\d*|OpenGL|Vulkan|Metal)(\s.*)?$/i, "")
         .replace(/\s*\(TM\)|\(R\)/gi, "")
         .replace(/, or similar$/, "")
         .trim();
    return s || null;
  }
  const isSoftGpu = r => /Basic Render Driver|SwiftShader|llvmpipe|softpipe|Software Rasterizer/i.test(r || "");
  const isIntegratedGpu = g => /UHD|HD Graphics|Iris|Radeon\(TM\) Graphics|Radeon Graphics|Vega \d+ Graphics|Radeon(\(TM\))? \d{3}M\b|Intel(\(R\))? Arc(\(TM\))? Graphics/i.test(g || "");
  function inferGpuOS(raw) {
    if (!raw) return null;
    if (/Direct3D|D3D1\d/.test(raw)) return "Windows";
    if (/Apple (M\d|GPU)|Metal/.test(raw)) return "Apple";
    if (/Adreno|Mali|PowerVR|Xclipse|Maleoon/.test(raw)) return "Android";
    return null;
  }
  function findDiscreteGpu(gl, hiGl, wgpu, wgpuLo) {
    if (!gl || !isIntegratedGpu(gl)) return null;
    if (hiGl && hiGl !== gl && !isIntegratedGpu(hiGl)) return hiGl;
    const makers = { nvidia: "NVIDIA", amd: "AMD", intel: "Intel", apple: "Apple", qualcomm: "Qualcomm", arm: "Arm" };
    const v = wgpu && makers[String(wgpu.vendor || "").toLowerCase()];
    const diff = wgpuLo && wgpu && ["vendor", "architecture", "device", "description"].some(k => (wgpuLo[k] || "") !== (wgpu[k] || ""));
    if (!v || (!diff && gl.toLowerCase().includes(v.toLowerCase()))) return null;
    if (wgpu.description && isIntegratedGpu(wgpu.description)) return null;
    const arch = String(wgpu.architecture || "").split("-").filter(Boolean).map(w => w[0].toUpperCase() + w.slice(1)).join(" ");
    return wgpu.description ? (cleanGpuName(wgpu.description) || wgpu.description) : [v, arch].filter(Boolean).join(" ");
  }

  const DC_ASN = new Set([13335, 209242, 16509, 14618, 15169, 396982, 19527, 8075, 8068, 14061, 63949, 20473, 16276, 24940, 31898, 45102, 37963, 132203, 45090, 9009, 60068, 212238, 51167, 136907, 55990, 906, 25820, 35916, 54600, 40065, 36352, 53667, 46562, 8100, 62904, 21859, 199524, 202422, 12876, 197540, 47583, 141995, 35913, 32613, 26496, 46606, 398101, 30633, 64267, 201814, 22612, 7979, 10439, 400328, 49981, 61317]);
  const DC_RE = /amazon|\baws\b|google cloud|google llc|microsoft|azure|digitalocean|linode|akamai|vultr|choopa|\bovh|hetzner|oracle|alibaba|aliyun|tencent|huawei cloud|contabo|leaseweb|m247|datacamp|cdn77|g-?core|hostinger|hosting|\bhost|server|cloud|data ?cent|colo|\bvps\b|dedicated|ionos|scaleway|kamatera|racknerd|frantech|psychz|quadranet|zenlayer|dmit|bandwagon|it7|cloudflare|fastly|packet|equinix|cogent|mullvad|proton|nordvpn|expressvpn|surfshark/i;
  function isDataCenterIp(geo) {
    if (!geo) return false;
    const asnNum = parseInt(String(geo.asn || "").replace(/^AS/i, ""), 10);
    const hay = [geo.isp, geo.org, geo.asFull, geo.asName, geo.ptr].filter(Boolean).join(" ");
    return !!(geo.hosting || geo.hostingInferred || (asnNum && DC_ASN.has(asnNum)) || DC_RE.test(hay));
  }
  const RELAY4 = [[104, 28], [172, 224], [172, 225], [172, 226], [146, 75], [140, 248]];
  function isAppleRelay(ip) {
    const s = String(ip || "");
    if (s.includes(":")) return /^(2606:54c0|2a02:26f7|2a04:4e41):/i.test(s);
    const [a, b] = s.split(".").map(Number);
    return RELAY4.some(([x, y]) => x === a && y === b);
  }

  function expandV6(ip) {
    const [h, tl = ""] = String(ip).toLowerCase().split("::");
    const H = h ? h.split(":") : [], T = tl ? tl.split(":") : [];
    return [...H, ...Array(Math.max(0, 8 - H.length - T.length)).fill("0"), ...T].map(g => g.padStart(4, "0"));
  }
  function extractV6Mac(ip) {
    if (!ip || !ip.includes(":")) return null;
    const g = expandV6(ip).map(x => parseInt(x, 16));
    if ((g[5] & 0xff) !== 0xff || (g[6] >> 8) !== 0xfe) return null;
    const b = [(g[4] >> 8) ^ 0x02, g[4] & 0xff, g[5] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
    return b.map(x => x.toString(16).padStart(2, "0")).join(":");
  }
  function netPrefix(ip) {
    if (!ip) return "";
    return ip.includes(":") ? expandV6(ip).slice(0, 4).join(":") : ip.split(".").slice(0, 2).join(".");
  }

  const JS_FEATURES = [
    [97, "findLast", () => Array.prototype.findLast],
    [98, "structuredClone", () => window.structuredClone],
    [117, "Object.groupBy", () => Object.groupBy],
    [119, "Promise.withResolvers", () => Promise.withResolvers],
    [121, "Array.fromAsync", () => Array.fromAsync],
    [122, "Set.prototype.union", () => Set.prototype.union],
    [128, "Promise.try", () => Promise.try],
    [129, "Intl.DurationFormat", () => Intl.DurationFormat],
    [134, "Error.isError", () => Error.isError],
    [135, "Float16Array", () => window.Float16Array],
    [136, "RegExp.escape", () => RegExp.escape]
  ];

  function inferOrigin({ langs = [], tz, ipcc, sys, ios }) {
    const first = langs[0] || "", lcc = langCC(first), tcc = tzCC(tz);
    const isEn = l => /^en\b/i.test(l || "");
    const plainEn = ios ? /^en$/i.test(first) : isEn(first);
    if (lcc && !plainEn) {
      if (tcc && tcc !== lcc && lcc !== ipcc && spokenIn(first).includes(tcc)) return { cc: tcc, from: ["langs", "tz"] };
      return { cc: lcc, from: tcc === lcc ? ["langs", "tz"] : ["langs"] };
    }
    const nextLang = langs.slice(1).find(l => !isEn(l) && langCC(l));
    if (nextLang) {
      const ncc = langCC(nextLang);
      return { cc: ncc, from: tcc === ncc ? ["langs", "tz"] : ["langs"] };
    }
    if (sys && sys.cc && sys.cc.length === 1 && (sys.from.length > 1 || sys.cc[0] === tcc)) {
      return { cc: sys.cc[0], from: sys.from };
    }
    if (tcc) return { cc: tcc, from: ["tz"] };
    if (lcc) return { cc: lcc, from: ["langs"] };
    return ipcc ? { cc: ipcc, from: ["geo"] } : null;
  }

  const SYS_LANG_FONTS = [
    ["CN", ["DengXian", "FangSong", "KaiTi", "SimHei", "STKaiti", "STSong", "STXihei", "PingFang SC", "Songti SC", "Microsoft YaHei"]],
    ["TW", ["DFKai-SB", "MingLiU", "PMingLiU", "PingFang TC", "Microsoft JhengHei"]],
    ["JP", ["BIZ UDGothic", "BIZ UDMincho", "Yu Mincho", "Meiryo", "MS Gothic"]],
    ["KR", ["Batang", "Gulim", "Dotum", "Malgun Gothic"]]
  ];
  const KBD_REGION = { AZERTY: ["FR", "BE"], QWERTZ: ["DE", "AT", "CH"], "ЙЦУКЕН": ["RU", "UA", "BY"], Hebrew: ["IL"], Greek: ["GR"] };
  function inferSystemLangs({ os, sysFonts = [], voices = [], kbd }) {
    const from = [], cc = [];
    const add = (list, src) => {
      for (const c of list) if (!cc.includes(c)) cc.push(c);
      if (list.length && !from.includes(src)) from.push(src);
    };
    if (os === "Windows") {
      for (const [c, fl] of SYS_LANG_FONTS) {
        const winOnly = fl.filter(f => !["PingFang SC", "Songti SC", "PingFang TC"].includes(f));
        if (winOnly.some(f => sysFonts.includes(f))) add([c], "fonts");
      }
      const vcc = Array.from(new Set(voices.map(langCC).filter(c => c && !/^(US|GB|AU|CA|IE|IN|NZ|ZA)$/.test(c))));
      if (vcc.length && vcc.length <= 4) add(vcc, "voices");
    }
    if (KBD_REGION[kbd]) add(KBD_REGION[kbd], "kbd");
    if (!cc.length && os !== "Windows") return false;
    return { cc, from };
  }


  /* ---------- Runtime State & UI Skeleton Builders ---------- */
  let R = {};
  let runSeq = 0;
  let completedSet = new Set();
  let activeGroup = "all";
  let searchQuery = "";
  let checkFilter = "all";
  let currentScene = store.get(SK.scene) === "privacy" ? "privacy" : "disguise";
  let targetCountry = store.get(SK.target) || "";
  let externalQueryIp = (() => {
    try { return (new URLSearchParams(location.search).get("ip") || "").trim(); } catch (e) { return ""; }
  })();

  const SCENARIOS_META = [
    ["ai", "AI 大模型", "ChatGPT / Claude / Gemini"],
    ["streaming", "流媒体与短视频", "Netflix / Disney+ / TikTok"],
    ["social", "社媒注册与养号", "X / Instagram / Reddit / TG"],
    ["captcha", "无感验证码免盾", "Turnstile / reCAPTCHA v3"],
    ["fintech", "金融支付与电商", "Stripe / PayPal / Amazon"],
    ["email", "SMTP 邮件信誉", "25 端口投递 / Spamhaus / PTR"]
  ];

  const SNIFFER_MAP = Object.fromEntries(SNIFFERS.map((s, idx) => [s[0], { idx: idx + 1, id: s[0], group: s[1], title: s[2], mask: s[3], desc: s[4] }]));
  const ROW_EL = {};
  const CHECK_EL = {};

  const ROUTES_META = [
    ["ex_self", "本站部署节点", "直接读取 TCP/TLS 原始包"],
    ["ex_cn", "中国大陆测速节点", "检验「绕过大陆」分流是否漏出真实宽带"],
    ["ex_intl", "国际通用 GeoIP 节点", "海外常规网站看到的代理出口"],
    ["ex_gpt", "OpenAI ChatGPT 边缘", "AI 专属分流规则出口"],
    ["ex_claude", "Anthropic Claude 边缘", "Claude 独立分流出口"],
    ["ex_cf", "Cloudflare 全球边缘", "CDN 协商协议与数据中心"],
    ["dns", "递归 DNS 解析器", "随机子域名实测上游解析服务器归属"],
    ["stack", "IPv4 / IPv6 双栈对照", "检验代理是否漏管 IPv6 导致直连裸奔"]
  ];
  const ROUTE_EL = {};

  function showToast(msg) {
    const el = $("#toastBar");
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => { el.hidden = true; }, 2200);
  }

  async function copyText(text, label = "已复制到剪贴板") {
    try {
      await navigator.clipboard.writeText(text);
      showToast(label);
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.cssText = "position:fixed;opacity:0;left:-9999px";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); showToast(label); } catch (x) {}
      ta.remove();
    }
  }

  function buildInitialDOM() {
    // 1. 20-segment health bar (flex-1 so any check count renders evenly)
    const segBar = $("#segBar");
    if (segBar) {
      segBar.innerHTML = CORE_CHECKS.map(([id, title]) =>
        `<span data-seg="${esc(id)}" title="${esc(title)}" class="flex-1 h-full rounded-full bg-gray-200 dark:bg-neutral-800 transition-colors"></span>`
      ).join("");
    }

    // 1b. 6 Business Scenario Suitability Skeleton Cards
    const sg = $("#scenarioGrid");
    if (sg) {
      sg.innerHTML = SCENARIOS_META.map(([id, name, sub]) => `
        <div data-scen="${esc(id)}" class="rounded-lg border border-gray-200/90 bg-gray-50/50 p-3 flex flex-col justify-between gap-2 dark:bg-neutral-800/40 dark:border-neutral-800">
          <div>
            <div class="flex items-center justify-between gap-1.5">
              <span class="text-xs font-semibold text-gray-900 dark:text-white truncate">${esc(name)}</span>
              <span class="sc-badge inline-flex items-center py-0.5 px-1.5 rounded text-[10px] font-semibold bg-gray-200/80 text-gray-600 dark:bg-neutral-700 dark:text-neutral-300">评估中</span>
            </div>
            <p class="text-[10.5px] text-gray-400 dark:text-neutral-500 truncate">${esc(sub)}</p>
          </div>
          <div>
            <div class="flex items-baseline justify-between gap-1 mb-1">
              <span class="sc-score font-mono text-lg font-bold tabular-nums text-gray-900 dark:text-white">--</span>
              <span class="text-[10px] font-mono text-gray-400">/ 100</span>
            </div>
            <div class="h-1.5 w-full rounded-full bg-gray-200 overflow-hidden dark:bg-neutral-700">
              <div class="sc-bar h-full rounded-full bg-blue-500 transition-all duration-300" style="width: 15%"></div>
            </div>
            <p class="sc-reason mt-1.5 text-[11px] leading-snug text-gray-500 dark:text-neutral-400 line-clamp-2">等待多源欺诈库与浏览器核验…</p>
          </div>
        </div>
      `).join("");
    }
    if (externalQueryIp) {
      const inp = $("#ipQueryInput");
      if (inp) inp.value = externalQueryIp;
    }

    // 2. Route Split Matrix
    const rm = $("#routeMatrix");
    if (rm) {
      rm.innerHTML = ROUTES_META.map(([id, name, sub]) => `
        <div data-route="${esc(id)}" class="px-5 py-2.5 flex items-center justify-between gap-3 hover:bg-gray-50/80 dark:hover:bg-neutral-800/50 transition">
          <div class="min-w-0">
            <div class="font-medium text-gray-800 dark:text-neutral-200">${esc(name)}</div>
            <div class="text-[11px] text-gray-400 dark:text-neutral-500 truncate">${esc(sub)}</div>
          </div>
          <div class="text-right min-w-0 max-w-[56%]">
            <div class="rt-val maskable font-mono text-xs font-medium text-gray-500 dark:text-neutral-400 truncate">探测中…</div>
            <div class="rt-sub maskable text-[11px] text-gray-400 dark:text-neutral-500 truncate"></div>
          </div>
        </div>
      `).join("");
      $$("[data-route]", rm).forEach(el => { ROUTE_EL[el.dataset.route] = el; });
    }

    // 3. 14 Core Checks + 4 Protocol Checks
    const renderCheckRows = (list, isProto) => list.map(([id, title]) => `
      <div data-ck="${esc(id)}" data-proto="${isProto ? "1" : "0"}" class="px-5 py-3 transition hover:bg-gray-50/70 dark:hover:bg-neutral-800/40">
        <div class="flex items-start justify-between gap-3">
          <div class="flex items-start gap-2.5 min-w-0">
            <span class="ck-badge mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold bg-gray-100 text-gray-500 dark:bg-neutral-800 dark:text-neutral-400">…</span>
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-xs font-semibold text-gray-900 dark:text-white">${esc(title)}</span>
                <span class="ck-tag hidden py-0.5 px-1.5 rounded text-[10px] font-medium"></span>
              </div>
              <p class="ck-val maskable mt-0.5 text-xs text-gray-600 dark:text-neutral-400 leading-relaxed">等待探针汇总…</p>
            </div>
          </div>
          <div class="flex items-center gap-1.5 shrink-0">
            <button type="button" data-retest="${esc(id)}" hidden class="ck-retest py-1 px-2 rounded-md text-[11px] font-medium border border-gray-200 bg-white text-gray-700 hover:bg-gray-50 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-700 transition">重测</button>
            <button type="button" data-howto="${esc(id)}" class="ck-howto py-1 px-2 rounded-md text-[11px] font-medium text-blue-600 hover:bg-blue-50 dark:text-blue-400 dark:hover:bg-blue-500/10 transition">原理</button>
          </div>
        </div>
        <div class="ck-drawer mt-2.5 ms-7 rounded-lg border border-gray-200/80 bg-gray-50 p-3 text-xs text-gray-700 space-y-1.5 dark:bg-neutral-800/70 dark:border-neutral-700 dark:text-neutral-300" hidden></div>
      </div>
    `).join("");

    const coreBox = $("#coreChecksList"), protoBox = $("#protoChecksList");
    if (coreBox) coreBox.innerHTML = renderCheckRows(CORE_CHECKS, false);
    if (protoBox) protoBox.innerHTML = renderCheckRows(PROTO_CHECKS, true);
    $$("[data-ck]").forEach(el => { CHECK_EL[el.dataset.ck] = el; });

    // 4. Category Tabs & 128 Sniffer Explorer Rows
    const tabsBox = $("#groupTabs");
    if (tabsBox) {
      const counts = {};
      for (const [, g] of SNIFFERS) counts[g] = (counts[g] || 0) + 1;
      const allTabs = [["all", "全部探针", SNIFFERS.length], ...GROUPS.map(([g, name]) => [g, name, counts[g] || 0])];
      tabsBox.innerHTML = allTabs.map(([g, name, cnt], idx) => `
        <button type="button" role="tab" data-gtab="${esc(g)}" aria-selected="${idx === 0 ? "true" : "false"}"
          class="gtab-btn shrink-0 py-1.5 px-3 inline-flex items-center gap-1.5 rounded-lg text-xs font-medium transition ${idx === 0
            ? "bg-blue-600 text-white shadow-2xs"
            : "bg-gray-100 text-gray-600 hover:bg-gray-200/70 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"}">
          <span>${esc(name)}</span>
          <span class="font-mono text-[11px] opacity-80">${cnt}</span>
        </button>
      `).join("");
    }

    const sc = $("#snifferContainer");
    if (sc) {
      sc.innerHTML = GROUPS.map(([gid, gtitle, gdesc]) => {
        const items = SNIFFERS.map((s, idx) => ({ s, idx: idx + 1 })).filter(x => x.s[1] === gid);
        return `
          <div data-gsec="${esc(gid)}" class="sniffer-group">
            <div class="px-5 py-2.5 bg-gray-50/90 border-b border-gray-100 flex flex-wrap items-center justify-between gap-2 dark:bg-neutral-800/60 dark:border-neutral-800">
              <div class="flex items-center gap-2">
                <span class="text-xs font-semibold text-gray-800 dark:text-neutral-200">${esc(gtitle)}</span>
                <span class="text-[11px] font-mono text-gray-400 dark:text-neutral-500">(${items.length} 项)</span>
              </div>
              <span class="text-[11px] text-gray-500 dark:text-neutral-400">${esc(gdesc)}</span>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:gap-px bg-gray-100 dark:bg-neutral-800">
              ${items.map(({ s: [id, , title, mask, desc], idx }) => `
                <div data-probe="${esc(id)}" data-g="${esc(gid)}" data-why="${esc(desc)}"
                  class="probe-row bg-white dark:bg-neutral-900 px-4 py-2.5 flex items-center justify-between gap-3 cursor-pointer hover:bg-blue-50/40 dark:hover:bg-neutral-800/80 transition">
                  <div class="flex items-center gap-2 min-w-0 shrink-0 max-w-[48%]">
                    <span class="font-mono text-[10px] text-gray-400 dark:text-neutral-500 w-7 shrink-0">#${String(idx).padStart(3, "0")}</span>
                    <span class="text-xs font-medium text-gray-700 dark:text-neutral-300 truncate">${esc(title)}</span>
                    <button type="button" data-tipbtn="${esc(id)}" class="tip-trigger shrink-0 inline-flex items-center justify-center size-4 rounded-full text-[10px] font-semibold bg-gray-100 text-gray-500 hover:bg-blue-100 hover:text-blue-700 dark:bg-neutral-800 dark:text-neutral-400" aria-label="查看原理">?</button>
                  </div>
                  <div class="probe-val ${mask ? "maskable " : ""}font-mono text-xs text-right text-gray-400 dark:text-neutral-500 truncate min-w-0 flex-1">检测中…</div>
                </div>
              `).join("")}
            </div>
          </div>
        `;
      }).join("");
      $$("[data-probe]", sc).forEach(el => { ROW_EL[el.dataset.probe] = el; });
    }

    // 5. Populate Target Country Select
    const sel = $("#targetSelect");
    if (sel) {
      const codes = Array.from(new Set(["US", "JP", "SG", "GB", "HK", "TW", "DE", "KR", "FR", "NL", "CA", "AU", "CH", "SE", "MY", "TH", "VN", "IN", "BR", "AE", "TR", "RU", ...Object.values(TZ_CC)])).sort((a, b) => countryName(a).localeCompare(countryName(b), "zh-CN"));
      sel.innerHTML = `<option value="">更多国家或地区…</option>` + codes.map(cc =>
        `<option value="${esc(cc)}">${esc(flagEmoji(cc) + " " + countryName(cc) + " (" + cc + ")")}</option>`
      ).join("");
    }
  }

  function updateProgress() {
    const cnt = completedSet.size;
    const total = SNIFFERS.length;
    const badge = $("#probeCountBadge");
    if (badge) badge.textContent = `${cnt} / ${total}`;
    const bar = $("#topProgBar");
    if (bar) bar.style.width = `${Math.min(100, Math.max(5, Math.round((cnt / total) * 100)))}%`;
    const txt = $("#liveStatusText");
    if (txt && !R.finished) {
      txt.textContent = `已完成 ${cnt} / ${total} 项无感嗅探…`;
    }
  }

  function setProbe(id, value, opts = {}) {
    const el = ROW_EL[id];
    completedSet.add(id);
    R.values = R.values || {};
    R.values[id] = opts.rawText != null ? opts.rawText : (opts.html ? el?.textContent || "" : String(value ?? ""));
    if (el) {
      const vEl = $(".probe-val", el);
      if (vEl) {
        if (opts.html) vEl.innerHTML = value;
        else vEl.textContent = value == null || value === "" ? "–" : String(value);
        vEl.className = `probe-val ${SNIFFER_MAP[id]?.mask ? "maskable " : ""}font-mono text-xs text-right truncate min-w-0 flex-1 ` +
          (opts.tone === "bad" ? "text-red-600 font-semibold dark:text-red-400"
            : opts.tone === "warn" ? "text-amber-600 font-semibold dark:text-amber-400"
            : opts.tone === "ok" ? "text-teal-700 font-medium dark:text-teal-400"
            : opts.na ? "text-gray-400 dark:text-neutral-500"
            : "text-gray-900 dark:text-neutral-100");
      }
      const baseDesc = SNIFFER_MAP[id]?.desc || "";
      el.dataset.why = opts.why ? `${baseDesc}\n\n${opts.why}` : baseDesc;
    }
    updateProgress();
  }

  function setNA(id, text = "当前环境不支持或未暴露") {
    setProbe(id, text, { na: true });
  }

  function setRouteRow(id, mainText, subText = "", tone = "neutral") {
    const el = ROUTE_EL[id];
    if (!el) return;
    const v = $(".rt-val", el), s = $(".rt-sub", el);
    if (v) {
      v.textContent = mainText || "不可达";
      v.className = "rt-val maskable font-mono text-xs font-medium truncate " + (
        tone === "bad" ? "text-red-600 dark:text-red-400"
          : tone === "warn" ? "text-amber-600 dark:text-amber-400"
          : tone === "ok" ? "text-teal-700 dark:text-teal-400"
          : "text-gray-800 dark:text-neutral-200"
      );
    }
    if (s) s.textContent = subText;
  }

  /* ---------- 128 Genuine Sniffer Implementations ---------- */

  // 1. Server-side L3/L4/L7 packet & HTTP probe (26 items: 18 net + 8 hdr)
  const isThreatCidrHit = h => ["attack", "spam", "tor", "threat"].includes(h?.kind) || (h?.pts || 0) > 0;

  function expectedDirectRttMs() {
    if (R.ipLat == null || R.ipLon == null || !Array.isArray(R.srvCoords) || R.srvCoords.length !== 2) return null;
    const km = haversineKm(R.ipLat, R.ipLon, R.srvCoords[0], R.srvCoords[1]);
    if (!Number.isFinite(km)) return null;
    // 海底/陆地光缆折算系数 (~1.45x 大圆光速往返 + 22ms 接入网与路由开销)
    return { km: Math.round(km), expectedMs: Math.round(km * 0.0145 + 22) };
  }

  function backfillExitMeta(meta = {}) {
    if (!meta) return;
    let changed = false;
    if (!R.ip && meta.ip) {
      R.ip = String(meta.ip).trim();
      const ipVerStr = R.ip.includes(":") ? "IPv6" : "IPv4";
      setProbe("ip", `${R.ip} (${ipVerStr})`);
      changed = true;
    }
    if (!R.ipCC && meta.cc) {
      R.ipCC = String(meta.cc).trim().toUpperCase();
      changed = true;
    }
    if (!R.ipCity && meta.city) {
      R.ipCity = meta.city;
      changed = true;
    }
    if (R.ipCC && (!R.srv || !R.srv.geo?.countryCode)) {
      const locParts = [`${flagEmoji(R.ipCC)} ${countryName(R.ipCC)}`, meta.region, meta.city || R.ipCity].filter(Boolean);
      setProbe("geo", `${locParts.join(" · ")}（${meta.source || "多源回填"}）`);
    }
    if (R.ipLat == null && meta.lat != null && meta.lon != null) {
      R.ipLat = +meta.lat;
      R.ipLon = +meta.lon;
      setProbe("coords", `${(+meta.lat).toFixed(4)}, ${(+meta.lon).toFixed(4)}`);
      changed = true;
    }
    if (!R.asn && meta.asn) {
      const a = String(meta.asn).trim();
      R.asn = a ? (a.toUpperCase().startsWith("AS") ? a.toUpperCase() : `AS${a}`) : "";
      changed = true;
    }
    if (!R.org && meta.org) {
      R.org = String(meta.org).trim();
      changed = true;
    }
    if ((R.asn || R.org) && (!R.srv || !(R.srv.geo?.isp || R.srv.geo?.org))) {
      setProbe("isp", [R.asn, R.org].filter(Boolean).join(" · "));
    }
    if (!R.ipTz && meta.timezone) {
      const off = tzOffsetMin(meta.timezone);
      R.ipTz = meta.timezone;
      R.ipTzOff = off;
      setProbe("tzip", `${meta.timezone} (UTC${fmtUtcOffset(off)})`);
      changed = true;
    }
    if (!R.netKind && (R.ip || R.asn || R.org)) {
      const isRelay = isAppleRelay(R.ip || "");
      const isDc = !isRelay && (meta.hosting === true || isDataCenterIp({ asn: R.asn, org: R.org, isp: R.org }));
      const isMob = !!meta.mobile;
      R.netKind = isRelay ? "relay" : isDc ? "dc" : isMob ? "mobile" : "isp";
      setProbe("nettype",
        isRelay ? "Apple iCloud 专用代理转发"
          : isDc ? "数据中心 / 云服务器机房线路 (IDC/VPS)"
          : isMob ? "蜂窝移动数据网络 (4G/5G)"
          : "家庭宽带 / 商业原生 ISP 线路",
        { tone: isDc ? "bad" : "ok" }
      );
      changed = true;
    }
    if (changed && R.ip) {
      const kpiIp = $("#kpiExitIp");
      if (kpiIp) kpiIp.textContent = R.ip;
      const kpiGeo = $("#kpiExitGeo");
      if (kpiGeo) {
        kpiGeo.textContent = [R.ipCC ? `${flagEmoji(R.ipCC)} ${countryName(R.ipCC)}` : "", R.ipCity, R.asn, R.org].filter(Boolean).join(" · ") || "已通过备用链路识别出口";
      }
      const ispBadge = $("#ispTypeBadge");
      if (ispBadge && R.netKind) {
        const isDc = R.netKind === "dc";
        ispBadge.textContent = R.netKind === "relay" ? "iCloud 代理" : isDc ? "机房 / VPS" : R.netKind === "mobile" ? "蜂窝移动" : "原生家宽/ISP";
        ispBadge.className = "inline-flex items-center py-0.5 px-2 rounded-full text-[11px] font-medium " + (
          isDc ? "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400"
            : "bg-teal-50 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400"
        );
      }
      if (!R.exits) R.exits = {};
      if (!R.exits.ex_self) {
        const lbl = [countryName(R.ipCC), R.ipCity, R.org].filter(Boolean).join(" · ");
        R.exits.ex_self = { ip: R.ip, cc: R.ipCC, label: lbl };
        setProbe("ex_self", `${R.ipCC ? flagEmoji(R.ipCC) + " " : ""}${R.ip}${lbl ? " · " + lbl : ""}`);
        setRouteRow("ex_self", `${R.ipCC ? flagEmoji(R.ipCC) + " " : ""}${R.ip}`, lbl, R.netKind === "dc" ? "warn" : "ok");
      }
    }
  }

  async function probeServer() {
    const t0 = Date.now();
    let data = null;
    try {
      data = await getJSON(`./api/who/me?t=${t0}`, 11000, "omit");
      if (!data) {
        data = await getJSON(`./api/who/me?t=${Date.now()}&r=retry`, 7500, "omit");
      }
      // If socket was freshly established and BPF sniffer buffer is 50ms behind, retry once cleanly
      if (data && (!data.packet || !data.packet.tcp)) {
        await new Promise(r => setTimeout(r, 160));
        const retry = await getJSON(`./api/who/me?t=${Date.now()}&r=1`, 5500, "omit").catch(() => null);
        if (retry && retry.packet && retry.packet.tcp) data = retry;
      }
    } catch (e) {}
    const t1 = Date.now();

    if (!data) {
      const onlySrv = ["ptr", "clock", "proto", "tcpfp", "ipquirk", "ja4t", "tunnel", "ja4", "ja3", "tlsext", "pqkex", "ech", "h2fp",
       "h_ua", "h_lang", "h_chua", "h_plat", "h_arch", "h_enc", "h_sec", "h_dnt"];
      if (!R.ip) onlySrv.unshift("ip", "geo", "coords", "isp", "nettype", "tzip");
      onlySrv.forEach(k => setNA(k, "服务端探针请求超时"));
      return;
    }

    R.srv = data;
    if (Array.isArray(data.serverCoords) && data.serverCoords.length === 2) {
      R.srvCoords = data.serverCoords;
    }
    const g = data.geo || data.ipGeo || {};
    if (g.city) R.ipCity = g.city;
    const pkt = data.packet || {};
    const tcp = pkt.tcp || null;
    const tls = pkt.tlsClientHello || pkt.tls || null;
    const hdr = data.headers || {};

    // Clock skew
    const srvEpoch = data.serverTimeMs || data.serverEpochMs;
    if (srvEpoch) {
      const skewMs = Math.round(srvEpoch - (t0 + t1) / 2);
      R.clockSkewMs = skewMs;
      const absSec = (Math.abs(skewMs) / 1000).toFixed(2);
      setProbe("clock", Math.abs(skewMs) < 1500 ? `同步良好 (误差 ${skewMs >= 0 ? "+" : ""}${skewMs} ms)` : `偏差 ${absSec} 秒`, {
        tone: Math.abs(skewMs) > 30000 ? "warn" : "ok"
      });
    } else setNA("clock");

    // IP & Geo
    const ip = data.clientIp || data.ip || g.ip || "";
    const cc = g.countryCode || "";
    R.ip = ip;
    R.ipCC = cc;
    const ipVerStr = data.ipVersion === 6 || ip.includes(":") ? "IPv6" : "IPv4";
    setProbe("ip", `${ip} (${ipVerStr})`);

    const locParts = [cc ? `${flagEmoji(cc)} ${countryName(cc)}` : "", g.region, g.city].filter(Boolean);
    setProbe("geo", locParts.length ? `${locParts.join(" · ")}（按 IP 库估）` : "未知位置", {
      why: `数据来源: ${g.source || "GeoIP"} · 邮编: ${g.postal || "–"}`
    });

    const lat = g.lat ?? g.latitude, lon = g.lon ?? g.longitude;
    if (lat != null && lon != null) {
      R.ipLat = +lat;
      R.ipLon = +lon;
      setProbe("coords", `${(+lat).toFixed(4)}, ${(+lon).toFixed(4)}`);
    } else setNA("coords");

    const asn = g.asn ? (String(g.asn).startsWith("AS") ? g.asn : `AS${g.asn}`) : "";
    const org = g.isp || g.org || g.asName || "";
    R.asn = asn;
    R.org = org;
    setProbe("isp", [asn, org].filter(Boolean).join(" · ") || "未知运营商", { why: g.asFull || "" });

    // Network type
    const isRelay = isAppleRelay(ip);
    const isDc = !isRelay && isDataCenterIp(g);
    const isMob = !!g.mobile;
    R.netKind = isRelay ? "relay" : isDc ? "dc" : isMob ? "mobile" : "isp";
    setProbe("nettype",
      isRelay ? "Apple iCloud 专用代理转发"
        : isDc ? "数据中心 / 云服务器机房线路 (IDC/VPS)"
        : isMob ? "蜂窝移动数据网络 (4G/5G)"
        : "家庭宽带 / 商业原生 ISP 线路",
      { tone: isDc ? "bad" : "ok" }
    );

    // IP Timezone
    if (g.timezone) {
      const off = tzOffsetMin(g.timezone);
      R.ipTz = g.timezone;
      R.ipTzOff = off;
      setProbe("tzip", `${g.timezone} (UTC${fmtUtcOffset(off)})`);
    } else setNA("tzip");

    setProbe("ptr", g.ptr || "无反向 PTR 记录", { na: !g.ptr });

    // Protocol & Cipher
    const ngTls = data.connection || data.nginxTls || {};
    setProbe("proto", [ngTls.httpVersion || ngTls.httpProtocol, ngTls.tlsProtocol, ngTls.tlsCipher].filter(Boolean).join(" · ") || "HTTPS");

    // Passive TCP SYN fingerprint
    if (tcp) {
      const osMap = { windows: "Windows (TTL 128)", apple: "macOS / iOS", linux: "Linux / Android", unix: "Linux / macOS / Unix" };
      const fam = tcp.osFamily || tcp.osGuess;
      const osTxt = osMap[fam] || tcp.osGuess || "未知内核";
      const obsTtl = tcp.observedTtl ?? tcp.ttl;
      const ws = tcp.wscale ?? tcp.windowScale ?? "?";
      const tun = tcp.tunnelGuess || tcp.tunnelHint;
      setProbe("tcpfp", `${osTxt} · 实测 TTL=${obsTtl}/${tcp.initialTtl} (${tcp.hops} 跳)`, {
        why: `TCP 选项序: ${(tcp.options || []).join(",")}\n服务端握手耗时: ${tcp.minHandshakeRttMs ?? tcp.handshakeRttMs ?? "?"} ms`
      });
      setProbe("ja4t", `${tcp.ja4t || "–"} · Win=${tcp.window} · MSS=${tcp.mss || "?"} · WS=${ws}`);

      const tunLabels = {
        ethernet: `标准以太网直连 (MTU ${tcp.mtu})`,
        pppoe: `PPPoE 光猫拨号宽带 (MTU ${tcp.mtu})`,
        wireguard: `疑似 WireGuard 隧道封装 (MTU ${tcp.mtu})`,
        ipsec_or_tun: `疑似 IPsec / 代理 TUN 虚拟网卡 (MTU ${tcp.mtu})`,
        openvpn_or_tun: `疑似 OpenVPN / 跨境隧道封装 (MTU ${tcp.mtu})`,
        jumbo_cloud: `云服务器内网巨型帧 (MTU ${tcp.mtu})`
      };
      setProbe("tunnel", tunLabels[tun] || (tcp.mtu ? `MTU ${tcp.mtu} (MSS ${tcp.mss})` : "未携带 MSS"), {
        tone: tun && !["ethernet", "pppoe"].includes(tun) ? "warn" : "neutral"
      });

      // IP layer DF / IPID / ECN & TCP Timestamp clock Hz + stateless SYN-spoof check
      const dfTxt = tcp.df === true ? "DF=1(不分片)" : tcp.df === false ? "DF=0(允许分片·macOS/BSD特征)" : "DF=?";
      const ipidStep = (tcp.synIpId != null && tcp.helloIpId != null)
        ? (tcp.synIpId === 0 && tcp.helloIpId === 0 ? "IPID=0恒零(Linux/Apple特征)" : `IPID ${tcp.synIpId}→${tcp.helloIpId}`)
        : (tcp.synIpId != null ? `SYN IPID=${tcp.synIpId}` : "IPID=–");
      const hzTxt = tcp.tsHz != null ? `TS时钟≈${tcp.tsHz}Hz` : (tcp.synTsval != null ? `TSval=${tcp.synTsval}` : "无TS时间戳");
      const ecnTxt = tcp.ecn ? "ECN开启" : "ECN未开";
      const spoofTxt = tcp.synSpoofSuspect ? " · 疑似无状态SYN改包！" : "";
      setProbe("ipquirk", `${dfTxt} · ${ipidStep} · ${hzTxt} · ${ecnTxt}${spoofTxt}`, {
        tone: tcp.synSpoofSuspect ? "bad" : "neutral",
        why: `TOS=0x${(tcp.tos || 0).toString(16)} · SYN TSval=${tcp.synTsval ?? "无"} · 估算内核节拍=${tcp.tsHz ?? "待二次包计算"} Hz`
      });
    } else {
      setNA("tcpfp", "连接复用未捕获新 SYN 包");
      setNA("ipquirk", "连接复用未捕获新 SYN 包");
      setNA("ja4t", "连接复用未捕获新 SYN 包");
      setNA("tunnel", "连接复用未捕获新 SYN 包");
    }

    // Passive TLS ClientHello fingerprint
    if (tls) {
      const hasGr = !!(tls.hasGrease ?? tls.grease);
      const extCnt = tls.extCount ?? tls.extensionsCount ?? 0;
      setProbe("ja4", tls.ja4 || "–", { why: `SNI: ${tls.sni || "–"} · ALPN: ${(tls.alpn || []).join(",")} · Hello长度: ${tls.helloLength || "?"}B` });
      setProbe("ja3", `${tls.ja3 || "–"} · GREASE ${hasGr ? "已注入(真浏览器特征)" : "无(疑似脚本/定制栈)"}`, {
        tone: hasGr ? "ok" : "warn",
        why: `加密套件数: ${tls.cipherCount || "?"} · 扩展数: ${extCnt}`
      });
      const alps = tls.alpsExtension ? "ALPS 已启用" : "无 ALPS";
      const ccAlg = (tls.certCompression || []).length ? `证书压缩(${tls.certCompression.join("/")})` : "无证书压缩";
      setProbe("tlsext", `${alps} · ${ccAlg} · ${extCnt} 个扩展`, {
        tone: !tls.alpsExtension && !(tls.certCompression || []).length ? "warn" : "ok"
      });
      R.srvPq = !!tls.pqSupported;
      R.srvPqGroup = tls.pqGroup || null;
      R.srvEch = !!tls.echExtension;
      setProbe("pqkex", tls.pqSupported ? `已启用 (${tls.pqGroup})` : `未启用 (KeyShare: ${(tls.keyShareGroups || []).join(",") || "经典椭圆曲线"})`, {
        tone: tls.pqSupported ? "ok" : "neutral"
      });
      setProbe("ech", tls.echExtension ? "ClientHello 携带 ECH 加密扩展" : "明文 SNI (未启用 ECH)");
    } else {
      ["ja4", "ja3", "tlsext", "pqkex", "ech"].forEach(k => setNA(k, "TLS 会话复用未重发 ClientHello"));
    }

    // Header order signature
    const hOrder = data.headerOrder || [];
    const hHash = data.headerOrderHash || (hOrder.length ? shortHash(await sha256(hOrder.map(s => s.toLowerCase()).join(","))) : "");
    setProbe("h2fp", hHash ? `${hHash} (${hOrder.length} 个请求头)` : "–", { why: hOrder.join(" → ") });

    // 8 HTTP Headers
    setProbe("h_ua", hdr["user-agent"] || "–");
    setProbe("h_lang", hdr["accept-language"] || "–");
    setProbe("h_chua", hdr["sec-ch-ua-full-version-list"] || hdr["sec-ch-ua"] || "未发送（Safari/Firefox 不发此头）", { na: !hdr["sec-ch-ua"] });
    setProbe("h_plat", [hdr["sec-ch-ua-platform"], hdr["sec-ch-ua-platform-version"], hdr["sec-ch-ua-mobile"]].filter(Boolean).join(" · ") || "未发送", { na: !hdr["sec-ch-ua-platform"] });
    setProbe("h_arch", [hdr["sec-ch-ua-arch"], hdr["sec-ch-ua-bitness"] ? `${hdr["sec-ch-ua-bitness"]}-bit` : "", hdr["sec-ch-ua-model"]].filter(Boolean).join(" · ") || "首次导航后按需携带", { na: !hdr["sec-ch-ua-arch"] });
    setProbe("h_enc", hdr["accept-encoding"] || "–");
    setProbe("h_sec", [hdr["sec-fetch-site"], hdr["sec-fetch-mode"], hdr["sec-fetch-dest"]].filter(Boolean).join(" / ") || "–");
    setProbe("h_dnt", `DNT: ${hdr["dnt"] || "未发"} · Sec-GPC: ${hdr["sec-gpc"] || "未发"}`);

    // Update KPI 3 & Route Matrix row 1 immediately
    $("#kpiExitIp").textContent = ip || "未知 IP";
    $("#kpiExitGeo").textContent = [cc ? `${flagEmoji(cc)} ${countryName(cc)}` : "", g.city, asn, org].filter(Boolean).join(" · ");
    const ispBadge = $("#ispTypeBadge");
    if (ispBadge) {
      ispBadge.textContent = isRelay ? "iCloud 代理" : isDc ? "机房 / VPS" : isMob ? "蜂窝移动" : "原生家宽/ISP";
      ispBadge.className = "inline-flex items-center py-0.5 px-2 rounded-full text-[11px] font-medium " + (
        isDc ? "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400"
          : "bg-teal-50 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400"
      );
    }
    setRouteRow("ex_self", `${flagEmoji(cc)} ${ip}`, [countryName(cc), g.city, org].filter(Boolean).join(" · "), isDc ? "warn" : "ok");

    // 若 probeLatency 先于慢链路 probeServer 返回，在此补齐服务端 TCP 握手耗时对比
    const lateSrvRtt = tcp ? (tcp.minHandshakeRttMs ?? tcp.handshakeRttMs ?? null) : null;
    if (lateSrvRtt != null) {
      R.srvTcpRtt = Math.round(lateSrvRtt);
      if (R.latDone && R.httpRtt != null) {
        const diff = Math.round(R.httpRtt - R.srvTcpRtt);
        const extraText = diff >= 45 ? ` · 浏览器多绕 +${diff} ms` : " · 往返吻合";
        setProbe("tcprtt", `浏览器 ${R.httpRtt} ms vs 服务端握手 ${R.srvTcpRtt} ms${extraText}`, {
          tone: diff >= 100 ? "bad" : diff >= 45 ? "warn" : "ok"
        });
        $("#kpiRttVal").textContent = `${R.httpRtt} ms / 握手 ${R.srvTcpRtt} ms`;
        updateUdpRttProbe();
      }
    }
  }

  // 1b. Multi-Source Egress Intelligence, BGP/RDAP Lease, 12 DNSBLs, /24 Dirty Neighbours & Active :443 Reality Back-Probe (12 items: reality443 + 11 rep_*)
  const REP_PROBE_IDS = ["reality443", "rep_score", "rep_votes", "rep_native", "rep_asn", "rep_lease", "rep_rpki", "rep_shodan", "rep_threat", "rep_dnsbl", "rep_cidr", "rep_neigh"];

  function applyIntelToProbes(intel) {
    if (!intel || !intel.ok) {
      REP_PROBE_IDS.forEach(k => setNA(k, "出口多源情报暂不可达"));
      const pill = $("#purityPill");
      if (pill && pill.textContent.includes("--")) {
        pill.textContent = "信誉超时";
      }
      return;
    }
    const p = intel.purity || {};
    const c = intel.consensus || {};
    const v = intel.votes || {};
    const ap = intel.asnProfile || {};
    const inf = ap.inferred || {};
    const ls = ap.lease || {};
    const ad = ap.abuseDensity || null;
    const t4 = intel.tls443 || {};
    const sh = intel.shodan || null;
    const th = intel.threat || {};
    const bl = intel.dnsbl || {};
    const ci = intel.cidr || {};
    const nb = ci.neighbours || {};
    const prefixTag = intel.isSelfEgress === false ? `[查 ${intel.targetIp}] ` : "";

    // Update KPI 3 purity pill & backfill missing exit metadata if this is the visitor's own egress
    if (intel.isSelfEgress !== false) {
      backfillExitMeta({
        ip: intel.targetIp,
        cc: c.country,
        city: c.city,
        region: c.region,
        timezone: c.timezone,
        asn: c.asn,
        org: c.org || ap.name,
        hosting: (v.hosting?.E || 0) >= 0.55 || inf.cls === "hosting" || !!ci.x4bDatacenter,
        mobile: inf.cls === "mobile",
        source: "8源情报共识"
      });
      const pill = $("#purityPill");
      if (pill && p.score != null) {
        pill.textContent = `纯净度 ${p.score}·${p.grade}`;
        pill.className = "inline-flex items-center py-0.5 px-2 rounded-full text-[11px] font-mono font-semibold " + (
          p.score >= 82 ? "bg-teal-50 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400"
            : p.score >= 58 ? "bg-amber-50 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400"
            : "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400"
        );
      }
      // Refine KPI 3 ISP badge if 8-source voting caught a fake-ISP or hosting node
      if ((v.hosting?.E >= 0.55 || inf.cls === "hosting" || ci.x4bDatacenter) && R.netKind === "isp") {
        R.netKind = "dc";
        setProbe("nettype", `多源投票识破机房/托管线路 (${Math.round((v.hosting?.E || 0.7) * 100)}% 置信)`, { tone: "bad" });
        const ispBadge = $("#ispTypeBadge");
        if (ispBadge) {
          ispBadge.textContent = inf.conflict ? "伪家宽机房" : "机房 / 托管";
          ispBadge.className = "inline-flex items-center py-0.5 px-2 rounded-full text-[11px] font-medium bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400";
        }
      }
    }

    // 1) reality443: Active :443 TLS & VLESS-Reality Camouflage Back-Probe
    if (!t4.probed) {
      setNA("reality443", "未启用 :443 主动回探");
    } else if (t4.realitySuspect) {
      setProbe("reality443", `${prefixTag}实锤伪装！非官方 ASN 却返回 ${t4.realityBrand || "大厂"} 证书 (${t4.realityDomain || "SNI"})`, {
        tone: "bad",
        why: `判定: ${t4.verdict} · 握手耗时: ${t4.rttMs ?? "?"}ms · TLS: ${t4.tlsVersion || "-"} · SANs: ${(t4.sans || []).join(", ")}`
      });
    } else if (t4.tlsActive) {
      const cn = t4.subjectCN || (t4.sans && t4.sans[0]) || "未声明域名";
      setProbe("reality443", `${prefixTag}开放 :443 TLS 服务 (CN=${cn}${t4.selfSignedOrIpCert ? " · 自签/IP证书" : ""})`, {
        tone: "warn",
        why: `签发机构: ${t4.issuerOrg || "自签/未知"} · 套件: ${t4.cipher || "-"} · 反向握手: ${t4.rttMs ?? "?"}ms`
      });
    } else if (t4.port443Open) {
      setProbe("reality443", `${prefixTag}开放 :443 TCP 端口（无标准 TLS 证书返回 · ${t4.rttMs ?? "?"}ms）`, { tone: "warn" });
    } else {
      setProbe("reality443", `${prefixTag}:443 端口关闭或静默丢包（典型家宽 NAT / 无公网服务端监听）`, { tone: "ok" });
    }

    // 2) rep_score: Purity Score & Ledger
    const dedLines = (p.deductions || []).map(d => `−${d.pts} [${d.label}] ${d.detail}`);
    const bonLines = (p.bonuses || []).map(b => `+${b.pts} [${b.label}]`);
    setProbe("rep_score", `${prefixTag}${p.score ?? "--"} / 100 · 等级 ${p.grade || "-"}（奖励 +${p.bonusTotal ?? 0} / 扣分 −${p.deductTotal ?? 0}）`, {
      tone: (p.score ?? 0) >= 82 ? "ok" : (p.score ?? 0) >= 58 ? "warn" : "bad",
      why: [...bonLines, ...dedLines].join("\n") || "基准分 92"
    });

    // 3) rep_votes: 8-Source Weighted Odds Voting
    const pct = x => `${Math.round((x?.E || 0) * 100)}%`;
    const maxAnon = Math.max(v.vpn?.E || 0, v.proxy?.E || 0, v.tor?.E || 0);
    setProbe("rep_votes", `${prefixTag}机房 ${pct(v.hosting)} · 代理 ${pct(v.proxy)} · VPN ${pct(v.vpn)} · Tor ${pct(v.tor)} · 风险分 ${c.riskScore ?? 0}`, {
      tone: maxAnon >= 0.45 || (v.hosting?.E || 0) >= 0.6 ? "bad" : maxAnon >= 0.2 || (v.hosting?.E || 0) >= 0.35 ? "warn" : "ok",
      why: (intel.sources || []).map(s => `${s.name}: ${s.country || "?"} · ${s.type || "-"} · risk=${s.risk ?? "-"} · ${JSON.stringify(s.flags || {})}`).join("\n")
    });

    // 4) rep_native: Native vs Broadcast IP & Geo Consensus
    const supPct = Math.round((c.countrySupport || 0) * 100);
    const natTxt = c.isNative === true
      ? `原生 IP（RIR 注册国 ${c.regCountry} = 定位国 ${c.country}）`
      : c.isNative === false
      ? `广播 IP！（RIR 注册于 ${c.regCountry}，BGP 广播至 ${c.country}）`
      : `定位 ${c.country || "未知"}（RIR 注册国未披露）`;
    setProbe("rep_native", `${prefixTag}${natTxt} · ${c.sourceCount || 0} 源共识 ${supPct}%`, {
      tone: c.isNative === false ? "warn" : supPct >= 85 ? "ok" : "neutral",
      why: (c.countries || []).map(x => `${x.cc}: ${x.by.join(", ")}`).join("\n")
    });

    // 5) rep_asn: BGP ASN Profile & PeeringDB Conflict
    const clsMap = { isp: "住宅/商业宽带 ISP", mobile: "移动蜂窝网络", hosting: "数据中心/云托管", cdn: "CDN 边缘网络", edu: "教育科研网", gov: "政企机构网", biz: "企业自用网" };
    const clsZh = clsMap[inf.cls] || inf.cls || "未知网络类型";
    const pdb = [ap.peeringdbType, ap.trafficRatio].filter(Boolean).join(" / ");
    setProbe("rep_asn", `${prefixTag}${c.asn ? "AS" + String(c.asn).replace(/^AS/i, "") : "ASN"} → ${clsZh}${pdb ? ` (PeeringDB: ${pdb})` : ""}${inf.conflict ? ` · ${inf.conflict}` : ""}`, {
      tone: inf.conflict || inf.cls === "hosting" ? "bad" : inf.cls === "isp" || inf.cls === "mobile" ? "ok" : "neutral",
      why: (inf.reasons || []).join("\n")
    });

    // 6) rep_lease: IP Leasing / Sub-allocation Broker Detection
    if (ls.leased) {
      setProbe("rep_lease", `${prefixTag}检出商业租赁/转售地址段（${(ls.reasons || []).join("；")}）`, { tone: "warn" });
    } else if (ls.possible) {
      setProbe("rep_lease", `${prefixTag}疑似近期子分配或转租网段（${(ls.reasons || []).join("；")}）`, { tone: "warn" });
    } else {
      setProbe("rep_lease", `${prefixTag}RIR 原始直配网段（未见 IPXO / InterLIR 租赁特征）`, {
        tone: "ok",
        why: intel.rdap?.name ? `RDAP NetName: ${intel.rdap.name} · 分配日: ${intel.rdap.regDate || "未知"}` : ""
      });
    }

    // 7) rep_rpki: BGP Announcement Scale, RPKI ROA & ASN Age
    const rpki = (ap.rpki || "unknown").toUpperCase();
    const v4Sz = ap.v4Size ? `${Number(ap.v4Size).toLocaleString("zh-CN")} 个 IPv4` : "规模未知";
    const regYr = ap.asnRegDate ? ` · 始于 ${String(ap.asnRegDate).slice(0, 4)} 年` : "";
    setProbe("rep_rpki", `${prefixTag}RPKI ${rpki} · 前缀 ${ap.prefixesV4Count ?? "?"} 条 (${v4Sz})${regYr}`, {
      tone: ap.rpki === "invalid" ? "bad" : ap.rpki === "valid" ? "ok" : "neutral"
    });

    // 8) rep_shodan: Shodan InternetDB Open Ports & CVEs
    if (!sh || (!sh.ports?.length && !sh.tags?.length && !sh.vulns?.length)) {
      setProbe("rep_shodan", `${prefixTag}无公网常驻暴露端口与已知 CVE 漏洞`, { tone: "ok" });
    } else {
      const pStr = (sh.ports || []).length ? `开放端口 [${sh.ports.slice(0, 8).join(",")}]` : "无常驻端口";
      const tStr = (sh.tags || []).length ? ` · 标签 ${sh.tags.join("/")}` : "";
      const vStr = (sh.vulns || []).length ? ` · 含 ${sh.vulns.length} 个历史 CVE！` : "";
      setProbe("rep_shodan", `${prefixTag}${pStr}${tStr}${vStr}`, {
        tone: (sh.vulns || []).length ? "bad" : (sh.ports || []).length ? "warn" : "ok",
        why: [...(sh.hostnames || []), ...(sh.cpes || []), ...(sh.vulns || [])].join(" · ")
      });
    }

    // 9) rep_threat: AlienVault OTX + StopForumSpam + Tor Onionoo
    const otxP = th.otx && !th.otx.benign ? (th.otx.pulses || 0) : 0;
    const sfsCnt = th.sfs?.appears ? (th.sfs.frequency || 1) : 0;
    const torHit = th.onionoo?.isTorExit || th.onionoo?.isTorRelay;
    const torNb = th.onionoo?.neighbourRelays || 0;
    const thHits = [];
    if (torHit) thHits.push("Tor 活跃节点");
    if (sfsCnt > 0) thHits.push(`StopForumSpam 举报 ${sfsCnt} 次`);
    if (otxP > 0) thHits.push(`OTX 威胁脉冲 ${otxP} 起`);
    if (torNb > 0) thHits.push(`同 /24 含 ${torNb} 个 Tor 中继`);
    setProbe("rep_threat", thHits.length ? `${prefixTag}${thHits.join(" · ")}` : `${prefixTag}OTX / StopForumSpam / Tor 名录零不良记录`, {
      tone: torHit || sfsCnt > 2 || otxP >= 3 ? "bad" : thHits.length ? "warn" : "ok"
    });

    // 10) rep_dnsbl: 12 DoH Real-time DNSBLs
    if ((bl.listedCount || 0) > 0) {
      setProbe("rep_dnsbl", `${prefixTag}上榜 ${bl.listedCount}/${bl.total || 12} 家：${(bl.listed || []).join(", ")}${bl.droneProxy ? " [DroneBL 开放代理]" : ""}`, {
        tone: "bad"
      });
    } else {
      setProbe("rep_dnsbl", `${prefixTag}通过全部 ${bl.total || 12} 家实时 DoH 黑名单核验（0 命中）`, { tone: "ok" });
    }

    // 11) rep_cidr: 15 CIDR Netsets & X4BNet DC/VPN
    const threatHits = (ci.hits || []).filter(isThreatCidrHit);
    const cidrNames = Array.from(new Set([
      ...(ci.hits || []).map(h => h.name),
      ci.x4bDatacenter ? "X4BNet 机房段" : "",
      ci.x4bVpn ? "X4BNet VPN/隧道段" : "",
      ci.openProxy ? "公开 SOCKS/HTTP 代理表" : ""
    ].filter(Boolean)));
    setProbe("rep_cidr", cidrNames.length ? `${prefixTag}命中 ${cidrNames.length} 项网段库：${cidrNames.join(" · ")}` : `${prefixTag}15 项公开恶意攻击、僵尸与 VPN 网段库零命中`, {
      tone: threatHits.length || ci.openProxy ? "bad" : cidrNames.length ? "warn" : "ok"
    });

    // 12) rep_neigh: /24 Dirty Neighbours & Whole-ASN Abuse Density
    const dirty = nb.dirtyCount || 0;
    const whole = (nb.wholeBlockListed || []).length > 0;
    const asnRatio = ad ? `${ad.per10k}/万IP (${ad.ratio}x 全网均值)` : "ASN 密度正常";
    setProbe("rep_neigh", `${prefixTag}同 /24 脏邻居 ${dirty} 个${whole ? " [整段封禁！]" : ""} · 全 ASN 滥用 ${asnRatio}`, {
      tone: whole || dirty >= 10 || (ad && ad.ratio >= 12) ? "bad" : dirty > 0 || (ad && ad.ratio >= 2.5) ? "warn" : "ok",
      why: (nb.lists || []).length ? `邻居上榜源: ${nb.lists.join(", ")}` : ""
    });
  }

  function syncExtIpBanner() {
    const banner = $("#extIpBanner");
    const tgtBadge = $("#scenarioTargetBadge");
    const ext = R.extIntel;
    if (!ext || !ext.ok) {
      if (banner) banner.hidden = true;
      if (tgtBadge) tgtBadge.textContent = "实时融合当前出口信誉 + 浏览器指纹";
      return;
    }
    if (banner) banner.hidden = false;
    const p = ext.purity || {}, c = ext.consensus || {}, ap = ext.asnProfile || {};
    $("#extIpVal").textContent = ext.targetIp || externalQueryIp;
    const pb = $("#extPurityBadge");
    if (pb) {
      pb.textContent = `纯净度 ${p.score ?? "--"} / 100 · 等级 ${p.grade || "-"}`;
      pb.className = "inline-flex items-center py-0.5 px-2 rounded-full text-[11px] font-semibold " + (
        (p.score ?? 0) >= 82 ? "bg-teal-600 text-white" : (p.score ?? 0) >= 58 ? "bg-amber-500 text-white" : "bg-red-600 text-white"
      );
    }
    const topDed = (p.deductions || [])[0];
    $("#extIpMeta").textContent = [
      c.country ? `${flagEmoji(c.country)} ${countryName(c.country)}` : "",
      c.isNative === false ? "广播IP" : c.isNative === true ? "原生IP" : "",
      c.asn ? `AS${String(c.asn).replace(/^AS/i, "")} ${ap.name || ""}`.trim() : "",
      topDed ? `主要扣分: ${topDed.label} (−${topDed.pts})` : "无显著扣分项"
    ].filter(Boolean).join(" · ");
    if (tgtBadge) tgtBadge.textContent = `当前评估外部查询 IP: ${ext.targetIp}`;
  }

  async function probeIntel() {
    const pSelf = (async () => {
      let d = await getJSON(`./api/who/intel?t=${Date.now()}`, 15000, "omit").catch(() => null);
      if (!d) d = await getJSON(`./api/who/intel?t=${Date.now()}&r=1`, 10000, "omit").catch(() => null);
      return d;
    })();
    const pExt = externalQueryIp
      ? getJSON(`./api/who/intel?ip=${encodeURIComponent(externalQueryIp)}&t=${Date.now()}`, 15000, "omit").catch(() => null)
      : Promise.resolve(null);

    const [selfData, extData] = await Promise.all([pSelf, pExt]);
    if (selfData && selfData.ok) {
      R.intel = selfData;
    }
    if (extData && extData.ok && !extData.isSelfEgress) {
      R.extIntel = extData;
    } else {
      R.extIntel = null;
    }
    if (R.intel && R.extIntel) {
      applyIntelToProbes(R.intel);
    }
    applyIntelToProbes(R.extIntel || R.intel);
    syncExtIpBanner();
    renderScenarios();
  }

  async function inspectCustomIp(rawIp) {
    const q = String(rawIp || "").trim();
    const btn = $("#btnQueryIp");
    if (!q) {
      externalQueryIp = "";
      R.extIntel = null;
      try {
        const u = new URL(location.href);
        u.searchParams.delete("ip");
        history.replaceState(null, "", u.pathname + u.search + u.hash);
      } catch (e) {}
      applyIntelToProbes(R.intel);
      syncExtIpBanner();
      renderScenarios();
      renderChecksAndScore(false);
      showToast("已切回本机当前出口情报");
      return;
    }
    if (btn) { btn.disabled = true; btn.textContent = "查询中…"; }
    const data = await getJSON(`./api/who/intel?ip=${encodeURIComponent(q)}&t=${Date.now()}`, 10000, "omit").catch(() => null);
    if (btn) { btn.disabled = false; btn.textContent = "查情报"; }
    if (!data || !data.ok) {
      showToast("请输入有效的公网 IPv4 或 IPv6 地址（不支持内网保留地址）");
      return;
    }
    externalQueryIp = data.targetIp || q;
    const inp = $("#ipQueryInput");
    if (inp) inp.value = externalQueryIp;
    try {
      const u = new URL(location.href);
      if (data.isSelfEgress) u.searchParams.delete("ip");
      else u.searchParams.set("ip", externalQueryIp);
      history.replaceState(null, "", u.pathname + u.search + u.hash);
    } catch (e) {}
    R.extIntel = data.isSelfEgress ? null : data;
    if (data.isSelfEgress) R.intel = data;
    applyIntelToProbes(R.extIntel || R.intel);
    syncExtIpBanner();
    renderScenarios();
    renderChecksAndScore(false);
    showToast(`已完成 ${externalQueryIp} 的多源信誉与 :443 证书穿透分析`);
  }

  // 2. Physical TCP Handshake RTT vs Browser Warm HTTP RTT + Micro-Burst Mux/Jitter Coalescing (2 items: tcprtt, muxjitter)
  async function probeLatency() {
    const samples = [];
    for (let i = 0; i < 5; i++) {
      const u = new URL(`./api/who/ping?seq=s${i}&t=${Date.now()}`, location.href).href;
      const t0 = performance.now();
      const ok = await fetch(u, { cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(4500) })
        .then(async r => {
          if (!r.ok) return false;
          const j = await r.json().catch(() => null);
          if (j && Array.isArray(j.serverCoords) && j.serverCoords.length === 2) R.srvCoords = j.serverCoords;
          return true;
        }, () => false);
      const wall = performance.now() - t0;
      if (!ok) continue;
      await new Promise(r => setTimeout(r, 5));
      const entries = performance.getEntriesByName(u);
      const e = entries[entries.length - 1];
      if (e && e.responseStart > e.requestStart && e.requestStart > 0) {
        samples.push(e.responseStart - e.requestStart);
      } else if (i > 0 && wall > 1) {
        samples.push(wall);
      }
    }
    R.httpRtt = samples.length ? Math.round(Math.min(...samples)) : null;

    // Micro-burst coalescing & jitter probe (6 pulses spaced ~8ms apart)
    try {
      const burstPromises = [];
      const sendTs = [];
      for (let b = 0; b < 6; b++) {
        sendTs.push(performance.now());
        const bu = `./api/who/ping?seq=b${b}&t=${Date.now()}_${b}`;
        burstPromises.push(
          fetch(bu, { cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(3500) })
            .then(async r => {
              const recv = performance.now();
              const j = r.ok ? await r.json().catch(() => null) : null;
              return j && j.serverPerfUs != null ? { b, sent: sendTs[b], recv, rtt: recv - sendTs[b], srvUs: j.serverPerfUs } : null;
            }, () => null)
        );
        if (b < 5) await new Promise(r => setTimeout(r, 8));
      }
      const bRes = (await Promise.all(burstPromises)).filter(Boolean).sort((a, b) => a.b - b.b);
      if (bRes.length >= 4) {
        const clientSpanMs = Math.max(1, bRes[bRes.length - 1].sent - bRes[0].sent);
        const srvSpanMs = Math.abs(bRes[bRes.length - 1].srvUs - bRes[0].srvUs) / 1000;
        const rtts = bRes.map(x => x.rtt);
        const meanRtt = rtts.reduce((a, b) => a + b, 0) / rtts.length;
        const stdRtt = Math.sqrt(rtts.reduce((s, x) => s + (x - meanRtt) ** 2, 0) / rtts.length);
        let coalescedPairs = 0;
        for (let k = 1; k < bRes.length; k++) {
          if (Math.abs(bRes[k].srvUs - bRes[k - 1].srvUs) < 900 && (bRes[k].sent - bRes[k - 1].sent) >= 5) {
            coalescedPairs++;
          }
        }
        R.muxBurst = { stdRtt: +stdRtt.toFixed(1), coalescedPairs, clientSpanMs: Math.round(clientSpanMs), srvSpanMs: +srvSpanMs.toFixed(1) };
        const isMux = coalescedPairs >= 3 || (srvSpanMs < clientSpanMs * 0.35 && clientSpanMs >= 25);
        setProbe("muxjitter", `RTT 抖动 σ=${stdRtt.toFixed(1)}ms · 发射跨度 ${Math.round(clientSpanMs)}ms → 服务端到达跨度 ${srvSpanMs.toFixed(1)}ms${isMux ? " (检出多路复用粘包合并特征)" : ""}`, {
          tone: isMux || stdRtt > 45 ? "warn" : "ok",
          why: `6 脉冲粘包对(<0.9ms间隔): ${coalescedPairs} 对 · 单次脉冲 RTT: ${rtts.map(x => Math.round(x) + "ms").join(", ")}`
        });
      } else {
        setNA("muxjitter", "微脉冲采样不足");
      }
    } catch (e) {
      setNA("muxjitter", "微脉冲探测受限");
    }

    // Timer coarsening check
    let step = Infinity, prev = performance.now();
    for (let i = 0, n = 0; i < 150000 && n < 5; i++) {
      const now = performance.now();
      if (now > prev) { step = Math.min(step, now - prev); prev = now; n++; }
    }
    R.coarseTimer = step >= 10;

    const tcp = R.srv?.packet?.tcp;
    const srvRtt = tcp ? (tcp.minHandshakeRttMs ?? tcp.handshakeRttMs ?? null) : null;
    R.srvTcpRtt = srvRtt != null ? Math.round(srvRtt) : null;
    R.latDone = true;

    if (R.httpRtt != null && R.srvTcpRtt != null) {
      const diff = Math.round(R.httpRtt - R.srvTcpRtt);
      const extraText = diff >= 45 ? ` · 浏览器多绕 +${diff} ms` : " · 往返吻合";
      setProbe("tcprtt", `浏览器 ${R.httpRtt} ms vs 服务端握手 ${R.srvTcpRtt} ms${extraText}`, {
        tone: diff >= 100 ? "bad" : diff >= 45 ? "warn" : "ok",
        why: `5 次热连接采样最小值: ${samples.map(x => Math.round(x) + "ms").join(", ")}\n服务端网卡 SYN→ClientHello 实测: ${R.srvTcpRtt}ms`
      });
      $("#kpiRttVal").textContent = `${R.httpRtt} ms / 握手 ${R.srvTcpRtt} ms`;
    } else if (R.httpRtt != null) {
      const geoBase = expectedDirectRttMs();
      if (geoBase) {
        const gDiff = Math.round(R.httpRtt - geoBase.expectedMs);
        const gTone = (gDiff >= 145 && R.httpRtt >= 290) ? "bad" : (gDiff >= 95 && R.httpRtt >= 230) ? "warn" : "ok";
        setProbe("tcprtt", `浏览器往返 ${R.httpRtt} ms vs 光缆物理基准 ~${geoBase.expectedMs} ms (${geoBase.km} km${gDiff >= 95 ? ` · 多绕 +${gDiff} ms` : ""})`, {
          tone: gTone,
          why: `5 次热连接采样最小值: ${samples.map(x => Math.round(x) + "ms").join(", ")}\n出口距服务端大圆距离: ${geoBase.km} km`
        });
      } else {
        const absTone = R.httpRtt >= 360 ? "bad" : R.httpRtt >= 270 ? "warn" : "neutral";
        setProbe("tcprtt", `浏览器往返 ${R.httpRtt} ms${R.httpRtt >= 270 ? "（高于洲际直连光缆物理上限）" : "（连接复用未重测握手）"}`, { tone: absTone });
      }
      $("#kpiRttVal").textContent = `HTTP ${R.httpRtt} ms`;
    } else {
      setNA("tcprtt", "网络计时受限");
      $("#kpiRttVal").textContent = "–";
    }
    updateUdpRttProbe();
  }

  // 3. Multi-target Outbound Exits, Dual-Stack & QUIC (9 items: ex_self..stack + quicfp)
  function parseCfTrace(txt) {
    return Object.fromEntries(String(txt || "").trim().split("\n").map(l => l.split("=")).filter(p => p.length === 2));
  }

  async function probeQuicAndExits() {
    R.exits = {};
    if (R.ip) {
      R.exits.ex_self = { ip: R.ip, cc: R.ipCC, label: [countryName(R.ipCC), R.srv?.geo?.city, R.org].filter(Boolean).join(" · ") };
      setProbe("ex_self", `${flagEmoji(R.ipCC)} ${R.ip} · ${R.exits.ex_self.label}`);
    } else {
      setNA("ex_self", "等待主连接返回");
    }

    // Mainland China exit probe (dual fallback: ipip.net + speedtest.cn)
    const pCn = (async () => {
      let ip = "", loc = "";
      const j1 = await getJSON("https://myip.ipip.net/json", 4800).catch(() => null);
      if (j1?.data?.ip) {
        ip = j1.data.ip;
        loc = (j1.data.location || []).filter(Boolean).join(" · ");
      } else {
        const j2 = await getJSON("https://forge.speedtest.cn/api/location/info", 4800).catch(() => null);
        if (j2?.ip) {
          ip = j2.ip;
          loc = [j2.country, j2.province, j2.city, j2.isp].filter(Boolean).join(" · ");
        } else {
          const t3 = await getText("https://myip.ipip.net", 4500).catch(() => "");
          const m = t3.match(/(\d+\.\d+\.\d+\.\d+)/);
          if (m) { ip = m[1]; loc = t3.replace(/\s+/g, " ").trim().slice(0, 50); }
        }
      }
      if (!ip) {
        setNA("ex_cn", "连接超时或被当前代理阻断");
        setRouteRow("ex_cn", "未连通", "大陆测速接口超时");
        return;
      }
      const isCn = /中国|北京|上海|广东|浙江|江苏|四川|湖北|福建|山东|河南|湖南|安徽|河北|陕西|辽宁|重庆|天津|广西|云南|江西|山西|贵州|吉林|黑龙江|内蒙古|新疆|甘肃|海南|宁夏|青海|西藏|电信|联通|移动/.test(loc) && !/香港|台湾|澳门/.test(loc);
      const cc = isCn ? "CN" : /香港/.test(loc) ? "HK" : /台湾/.test(loc) ? "TW" : "";
      R.exits.ex_cn = { ip, cc, label: loc };
      const leak = isCn && R.ipCC && R.ipCC !== "CN";
      setProbe("ex_cn", `${cc ? flagEmoji(cc) + " " : ""}${ip} · ${loc}`, { tone: leak ? "bad" : "neutral" });
      setRouteRow("ex_cn", `${cc ? flagEmoji(cc) + " " : ""}${ip}`, loc, leak ? "bad" : "ok");
    })();

    // International GeoIP exit (api.ip.sb + fallback ipwho.is)
    const pIntl = (async () => {
      let j = await getJSON("https://api.ip.sb/geoip", 6500).catch(() => null);
      if (!j || !j.ip) {
        const j2 = await getJSON("https://ipwho.is/", 6500).catch(() => null);
        if (j2 && j2.ip) {
          j = {
            ip: j2.ip,
            country_code: j2.country_code,
            region: j2.region,
            city: j2.city,
            timezone: j2.timezone?.id || (typeof j2.timezone === "string" ? j2.timezone : ""),
            latitude: j2.latitude,
            longitude: j2.longitude,
            asn: j2.connection?.asn,
            organization: j2.connection?.isp || j2.connection?.org
          };
        }
      }
      if (!j?.ip) {
        setNA("ex_intl", "国际探针不可达");
        setRouteRow("ex_intl", "不可达", "");
        return;
      }
      const cc = j.country_code || "";
      const sub = [countryName(cc), j.city, j.organization || j.isp].filter(Boolean).join(" · ");
      R.exits.ex_intl = { ip: j.ip, cc, label: sub };
      setProbe("ex_intl", `${flagEmoji(cc)} ${j.ip} · ${sub}`);
      setRouteRow("ex_intl", `${flagEmoji(cc)} ${j.ip}`, sub, "ok");
      backfillExitMeta({
        ip: j.ip,
        cc,
        city: j.city,
        region: j.region,
        timezone: j.timezone,
        lat: j.latitude,
        lon: j.longitude,
        asn: j.asn,
        org: j.organization || j.isp,
        source: "国际客户端 GeoIP 备援"
      });
    })();

    // ChatGPT, Claude, Cloudflare edge traces
    const runTraceProbe = async (key, url, name) => {
      const raw = await getText(url, 6500).catch(() => "");
      const kv = parseCfTrace(raw);
      if (!kv.ip) {
        setNA(key, `${name} 边缘不可达或被拦截`);
        setRouteRow(key, "不可达 / 被阻断", name);
        return null;
      }
      const cc = kv.loc || "";
      const sub = `${countryName(cc)} · 边缘节点 ${kv.colo || "?"} · ${kv.http || "h2"}`;
      R.exits[key] = { ip: kv.ip, cc, colo: kv.colo, http: kv.http, kex: kv.kex, sni: kv.sni, warp: kv.warp, gateway: kv.gateway, label: sub };
      setProbe(key, `${flagEmoji(cc)} ${kv.ip} · ${sub}`);
      setRouteRow(key, `${flagEmoji(cc)} ${kv.ip}`, sub, "ok");
      if (key === "ex_cf") {
        backfillExitMeta({ ip: kv.ip, cc, source: "Cloudflare Trace 备援" });
      }
      return kv;
    };

    const pGpt = runTraceProbe("ex_gpt", "https://chatgpt.com/cdn-cgi/trace", "ChatGPT");
    const pClaude = runTraceProbe("ex_claude", "https://claude.ai/cdn-cgi/trace", "Claude");
    const pCf = runTraceProbe("ex_cf", "https://www.cloudflare.com/cdn-cgi/trace", "Cloudflare");

    // Dual-stack IPv4 vs IPv6 independent probe
    const pStack = (async () => {
      const [r4, r6] = await Promise.all([
        getJSON("https://ipv4.icanhazip.com", 4500).catch(() => getText("https://ipv4.icanhazip.com", 4500).then(s => ({ ip: s.trim() }), () => null)),
        getText("https://ipv6.icanhazip.com", 4500).then(s => ({ ip: s.trim() }), () => null)
      ]);
      const v4 = r4?.ip || "";
      const v6 = r6?.ip && r6.ip.includes(":") ? r6.ip : "";
      R.stack = { v4, v6 };
      setProbe("stack", `IPv4: ${v4 || "无"} · IPv6: ${v6 || "未启用/仅IPv4"}`);
      setRouteRow("stack", v4 && v6 ? "IPv4 + IPv6 双栈在线" : v4 ? "纯 IPv4 链路" : "纯 IPv6 链路", `v4: ${v4 || "–"} / v6: ${v6 || "无"}`, v4 && v6 ? "warn" : "ok");
    })();

    const [, , , , cfKv] = await Promise.all([pCn, pIntl, pGpt, pClaude, pCf, pStack]);
    const edgeKv = cfKv || R.exits.ex_gpt || R.exits.ex_claude || {};
    R.cfEdge = edgeKv;

    // WARP & Gateway
    if (edgeKv.warp) {
      setProbe("warp", `WARP: ${edgeKv.warp} · Gateway: ${edgeKv.gateway || "off"}`, {
        tone: edgeKv.warp !== "off" ? "ok" : "neutral"
      });
    } else setNA("warp", "未经过 Cloudflare 边缘");

    // QUIC / HTTP/3 detection
    const navProtos = performance.getEntriesByType("navigation").concat(performance.getEntriesByType("resource")).map(e => e.nextHopProtocol).filter(Boolean);
    const hasH3 = navProtos.some(p => /^h3/i.test(p)) || [R.exits.ex_cf, R.exits.ex_gpt, R.exits.ex_claude].some(x => x && /http\/3|h3/i.test(x.http || ""));
    R.hasH3 = hasH3;
    setProbe("quicfp", hasH3 ? "已连通 HTTP/3 (UDP 443 QUIC 畅通)" : "当前走 TCP HTTP/2（代理或防火墙未放行 UDP 443 QUIC）", {
      tone: hasH3 ? "ok" : "neutral"
    });

    // Update split summary badge
    const prefixes = new Set(Object.values(R.exits).map(x => netPrefix(x?.ip)).filter(Boolean));
    const badge = $("#splitSummaryBadge");
    if (badge) {
      badge.textContent = prefixes.size > 1 ? `分流到 ${prefixes.size} 个网段` : "全局单一出口";
      badge.className = "inline-flex items-center py-0.5 px-2.5 rounded-full text-xs font-medium " + (
        R.exits.ex_cn?.cc === "CN" && R.ipCC && R.ipCC !== "CN"
          ? "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400"
          : prefixes.size > 1
          ? "bg-amber-50 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400"
          : "bg-teal-50 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400"
      );
    }
    R.exitsDone = true;
  }

  // 4. Recursive DNS Resolver Probe (1 item: dns)
  const CC_NAME_MAP = { "Hong Kong": "HK", "Macao": "MO", "Macau": "MO", "Taiwan": "TW", "South Korea": "KR", "Russia": "RU", "Vietnam": "VN", "Turkey": "TR", "Türkiye": "TR", "The Netherlands": "NL", "Netherlands": "NL", "United States": "US", "United Kingdom": "GB", "China": "CN", "Japan": "JP", "Singapore": "SG", "Germany": "DE", "France": "FR", "Canada": "CA", "Australia": "AU" };
  function resolveEnglishCountry(name) {
    if (!name) return null;
    if (CC_NAME_MAP[name]) return CC_NAME_MAP[name];
    if (!resolveEnglishCountry._cache && REG_EN) {
      const m = {};
      const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      for (const x of A) for (const y of A) {
        const c = x + y;
        try { const n = REG_EN.of(c); if (n && n !== c && !(n in m)) m[n] = c; } catch (e) {}
      }
      resolveEnglishCountry._cache = m;
    }
    return (resolveEnglishCountry._cache && resolveEnglishCountry._cache[name]) || null;
  }

  async function probeDns() {
    const randHex1 = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("");
    const randHex2 = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("");
    const [j1, j2] = await Promise.all([
      getJSON(`https://${randHex1}.edns.ip-api.com/json`, 6500).catch(() => null),
      getJSON(`https://${randHex2}.edns.ip-api.com/json`, 6500).catch(() => null)
    ]);
    const j = j1?.dns ? j1 : j2;
    if (!j || !j.dns) {
      R.dnsCC = null;
      R.dnsClass = null;
      setNA("dns", "DNS 探针被拦截或超时");
      setNA("ecs", "上游递归集群不可达");
      setRouteRow("dns", "未测出", "edns 探针超时");
      return;
    }
    const d = j.dns;
    const parts = String(d.geo || "").split(" - ");
    const cname = (parts[0] || "").trim();
    const org = parts.slice(1).join(" - ").trim();
    const cc = resolveEnglishCountry(cname);
    const ecsIp = j.edns?.ip || j2?.edns?.ip || "";
    const ecsGeo = j.edns?.geo || j2?.edns?.geo || "";
    R.dnsCC = cc;
    R.dnsIp = d.ip || "";
    R.dnsOrg = org || cname;
    R.ecsIp = ecsIp;

    // Collect multi-resolver cluster & classify DNS alignment (own / public / same / leak / leak-cn)
    const resolvers = Array.from(new Set([j1?.dns?.ip, j2?.dns?.ip].filter(Boolean)));
    const isPublicAnycast = /Google|Cloudflare|Quad9|OpenDNS|Cisco|NextDNS|AdGuard|Control D|CleanBrowsing/i.test(org);
    const sameOrg = R.org && org && (org.toLowerCase().includes(R.org.toLowerCase().split(/\s+/)[0]) || R.org.toLowerCase().includes(org.toLowerCase().split(/\s+/)[0]));
    let dnsClass = "same", clsLabel = "同国合规解析";
    if (cc === "CN" && R.ipCC && R.ipCC !== "CN") {
      dnsClass = "leak-cn";
      clsLabel = "国内 DNS 致命抢答泄漏";
    } else if (cc && R.ipCC && cc !== R.ipCC) {
      dnsClass = isPublicAnycast ? "public-cross" : "leak";
      clsLabel = isPublicAnycast ? `公共 Anycast 跨国节点 (${org})` : `跨国第三方递归 (${countryName(cc)})`;
    } else if (sameOrg) {
      dnsClass = "own";
      clsLabel = "本网 ISP 原生递归 (最优隐蔽度)";
    } else if (isPublicAnycast) {
      dnsClass = "public";
      clsLabel = `同国公共 DoH/Anycast (${org})`;
    }
    R.dnsClass = dnsClass;

    const leak = cc && R.ipCC && cc !== R.ipCC;
    setProbe("dns", `${flagEmoji(cc)} ${d.ip || ""} · ${countryName(cc)} (${org || cname})`, {
      tone: leak && cc === "CN" ? "bad" : leak ? "warn" : "ok"
    });
    setProbe("ecs", `${clsLabel} · 采样 ${resolvers.length} 节点 · ${ecsIp ? `暴露 ECS 子网 ${ecsIp}${ecsGeo ? " (" + ecsGeo + ")" : ""}` : "无 ECS 客户端子网泄露"}`, {
      tone: dnsClass === "leak-cn" ? "bad" : (dnsClass === "leak" || (ecsIp && netPrefix(ecsIp) !== netPrefix(R.ip))) ? "warn" : "ok",
      why: `观测递归节点: ${resolvers.join(", ")}\n判定等级: ${dnsClass}`
    });
    setRouteRow("dns", `${flagEmoji(cc)} ${countryName(cc)}`, `${d.ip || ""} · ${clsLabel}`, leak ? "warn" : "ok");
  }

  function updateUdpRttProbe() {
    if (R.rtc === "off") {
      return setNA("udprtt", "WebRTC 已禁用");
    }
    if (!R.rtcDone) return;
    if (R.stunRttMs == null) {
      setProbe("udprtt", "未收到公网 STUN UDP 响应（UDP 被屏蔽或仅 mDNS）", { tone: "neutral" });
      return;
    }
    if (R.httpRtt != null) {
      const delta = Math.round(R.stunRttMs - R.httpRtt);
      const sign = delta >= 0 ? `+${delta}` : `${delta}`;
      const suspect = Math.abs(delta) >= 95;
      setProbe("udprtt", `STUN UDP 候选 ${R.stunRttMs} ms vs HTTP TCP ${R.httpRtt} ms (差值 ${sign} ms)`, {
        tone: suspect ? "warn" : "ok",
        why: delta <= -65
          ? "UDP 显著快于 HTTP TCP：高度疑似代理仅接管了 TCP，而 UDP 直接走本地物理宽带穿透！"
          : delta >= 110
          ? "UDP 显著慢于 TCP：疑似经过 UDP-over-TCP (UoT) 二次隧道封装或远端中继。"
          : "UDP 与 TCP 往返时延量级吻合。"
      });
    } else {
      setProbe("udprtt", `STUN UDP 候选握手 ${R.stunRttMs} ms`);
    }
  }

  // 5. WebRTC STUN, UDP Timing & LAN mDNS Probe (3 items: webrtc, udprtt, lan)
  async function probeWebrtc() {
    const RTCPeer = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (!RTCPeer) {
      R.rtc = "off";
      R.rtcDone = true;
      setNA("webrtc", "WebRTC 已禁用");
      setNA("udprtt", "WebRTC 已禁用");
      setNA("lan", "WebRTC 已禁用");
      return;
    }
    const pubIps = new Set(), lanItems = new Set();
    let firstSrflxMs = null;
    let pc = null;
    try {
      pc = new RTCPeer({ iceServers: [{ urls: ["stun:stun.cloudflare.com:3478", "stun:stun.l.google.com:19302"] }] });
      pc.createDataChannel("p");
      let tStart = performance.now();
      const done = new Promise(resolve => {
        const timer = setTimeout(resolve, 2600);
        pc.onicecandidate = ev => {
          if (!ev || !ev.candidate) { clearTimeout(timer); resolve(); return; }
          const c = ev.candidate.candidate || "";
          const mLocal = c.match(/([0-9a-fA-F-]{8,}\.local)\b/);
          if (mLocal) lanItems.add(mLocal[1]);
          const ipMatch = c.match(/(?:\b|(?:candidate:\S+\s+\d+\s+\S+\s+\d+\s+))((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})\b/);
          const addr = ev.candidate.address || (ipMatch && ipMatch[1]) || "";
          if (!addr || addr.endsWith(".local")) return;
          if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fc|fd|fe80:)/i.test(addr)) {
            lanItems.add(addr);
          } else if (addr !== "0.0.0.0" && addr !== "::") {
            if (firstSrflxMs == null) firstSrflxMs = Math.max(1, Math.round(performance.now() - tStart));
            pubIps.add(addr);
          }
        };
      });
      const offer = await pc.createOffer();
      tStart = performance.now();
      await pc.setLocalDescription(offer);
      await done;
    } catch (e) {}
    try { if (pc) pc.close(); } catch (e) {}

    const pubList = Array.from(pubIps);
    const lanList = Array.from(lanItems);
    R.rtc = pubList;
    R.lan = lanList;
    R.stunRttMs = firstSrflxMs;
    R.rtcDone = true;

    if (!pubList.length) {
      setProbe("webrtc", "安全（未暴露公网 STUN 候选地址）", { tone: "ok" });
    } else {
      const known = new Set([R.ip, R.stack?.v4, R.stack?.v6].filter(Boolean));
      const leaked = pubList.filter(x => !known.has(x) && netPrefix(x) !== netPrefix(R.ip));
      setProbe("webrtc", pubList.join(" · ") + (leaked.length ? " (与当前代理出口不符！)" : " (与出口一致)"), {
        tone: leaked.length ? "bad" : "ok"
      });
    }
    updateUdpRttProbe();

    const realLan = lanList.filter(x => !x.endsWith(".local"));
    setProbe("lan", realLan.length ? `暴露真实局域网 IP: ${realLan.join(", ")}` : lanList.length ? `已由 mDNS 隐藏 (${lanList[0]})` : "未暴露局域网候选", {
      tone: realLan.length ? "warn" : "ok"
    });
  }

  // 6. IPv6 EUI-64 Hardware MAC Leak Check (1 item: v6mac)
  function probeV6Mac() {
    const v6Pool = [R.ip, R.stack?.v6, ...(Array.isArray(R.rtc) ? R.rtc : []), ...Object.values(R.exits || {}).map(x => x?.ip)].filter(x => x && String(x).includes(":"));
    if (!v6Pool.length) {
      R.v6mac = null;
      setProbe("v6mac", "当前无 IPv6 流量（无网卡 MAC 泄露风险）", { tone: "ok" });
      return;
    }
    const mac = v6Pool.map(extractV6Mac).find(Boolean) || null;
    R.v6mac = mac;
    if (mac) {
      setProbe("v6mac", `高危：从 IPv6 提取出物理网卡 MAC ${mac}`, { tone: "bad" });
    } else {
      setProbe("v6mac", `安全（已启用 IPv6 隐私临时随机后缀，共检验 ${v6Pool.length} 个地址）`, { tone: "ok" });
    }
  }

  // 7. Locale, Timezone, Keyboard & Offline Speech Voices (10 items: loc)
  function probeLocale() {
    const langs = Array.from(navigator.languages || (navigator.language ? [navigator.language] : []));
    R.langs = langs;
    setProbe("langs", langs.length ? `${langs.join(", ")} (${languageName(langs[0])})` : "–");

    let ro = {};
    try { ro = Intl.DateTimeFormat().resolvedOptions(); } catch (e) {}
    R.tz = ro.timeZone || "";
    const intlOff = R.tz ? tzOffsetMin(R.tz) : null;
    const dateOff = -new Date().getTimezoneOffset();
    R.tzOff = intlOff;
    R.dateOff = dateOff;

    setProbe("locale", [ro.locale, ro.calendar && `历法:${ro.calendar}`, ro.numberingSystem && `数字:${ro.numberingSystem}`].filter(Boolean).join(" · ") || "–");
    setProbe("tz", R.tz ? `${R.tz} · ${tzGenericLabel(R.tz)} (UTC${fmtUtcOffset(intlOff)})` : "未知时区");

    const tzMatch = intlOff == null || intlOff === dateOff;
    setProbe("tzoff", tzMatch
      ? `一致 (Date 偏移 UTC${fmtUtcOffset(dateOff)} = Intl 时区)`
      : `矛盾！Date 报 UTC${fmtUtcOffset(dateOff)} ≠ Intl 报 UTC${fmtUtcOffset(intlOff)}`, {
      tone: tzMatch ? "ok" : "bad"
    });

    let h12 = false, sampleTime = "";
    try {
      const dtf = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "numeric" });
      h12 = !!dtf.resolvedOptions().hour12;
      sampleTime = dtf.format(new Date(2026, 0, 1, 15, 30));
    } catch (e) {}
    R.h12 = h12;
    setProbe("hour", `${h12 ? "12 小时制" : "24 小时制"} (示例: ${sampleTime || "15:30"})`);

    let firstDay = "未知";
    try {
      const loc = new Intl.Locale(ro.locale || navigator.language || "zh-CN");
      const wk = loc.getWeekInfo ? loc.getWeekInfo() : loc.weekInfo;
      if (wk?.firstDay) firstDay = ({ 1: "周一 (中国/欧洲习惯)", 7: "周日 (美国/日本习惯)", 6: "周六 (中东习惯)" })[wk.firstDay] || `星期 ${wk.firstDay}`;
    } catch (e) {}
    setProbe("week", firstDay);

    const numFmt = (1234567.89).toLocaleString();
    const dateFmt = new Date(2026, 10, 5).toLocaleDateString();
    setProbe("fmt", `${numFmt} · ${dateFmt}`);

    if (typeof Intl.supportedValuesOf === "function") {
      const keys = ["timeZone", "currency", "unit", "calendar", "collation", "numberingSystem"];
      const counts = keys.map(k => { try { return Intl.supportedValuesOf(k).length; } catch (e) { return 0; } });
      setProbe("icu", `时区 ${counts[0]} · 货币 ${counts[1]} · 单位 ${counts[2]} · 历法 ${counts[3]}`, {
        why: keys.map((k, i) => `${k}: ${counts[i]}`).join(" · ")
      });
    } else setNA("icu");

    // ICU Collator phonetic/stroke/diacritic order & ListFormat locale check
    try {
      const col = new Intl.Collator();
      const colLoc = col.resolvedOptions().locale || "";
      const colType = col.resolvedOptions().collation || "default";
      const cjkOrder = ["中", "啊", "阿", "波"].sort(col.compare).join("");
      const latOrder = ["z", "ä", "ö", "a"].sort(col.compare).join("");
      const lf = typeof Intl.ListFormat === "function" ? new Intl.ListFormat(undefined, { style: "long", type: "conjunction" }).format(["A", "B"]) : "";
      R.collatorLocale = colLoc;
      setProbe("intlcoll", `Collator=${colLoc} (${colType}) · 汉字序[${cjkOrder}] · 列表[${lf || "–"}]`, {
        why: `拉丁变音序: ${latOrder} · 若伪装英语区但默认 Collator 仍按拼音排序 "啊阿波中"，即暴露底层中文 ICU 默认区域`
      });
    } catch (e) { setNA("intlcoll"); }
  }

  async function probeKeyboard() {
    if (!navigator.keyboard || !navigator.keyboard.getLayoutMap) {
      R.kbd = null;
      return setNA("kbd", "仅 Chromium 桌面端支持");
    }
    const map = await within(navigator.keyboard.getLayoutMap(), 1500, null);
    if (!map || !map.size) {
      R.kbd = null;
      return setNA("kbd", "未返回键位映射");
    }
    const q = map.get("KeyQ") || "", w = map.get("KeyW") || "", y = map.get("KeyY") || "", semi = map.get("Semicolon") || "";
    let layout = "QWERTY";
    if (q === "a" && w === "z") layout = "AZERTY";
    else if (y === "z") layout = "QWERTZ";
    else if (/[а-яё]/i.test(q)) layout = "ЙЦУКЕН";
    else if (/[\u0590-\u05ff]/.test(q)) layout = "Hebrew";
    else if (/[\u0370-\u03ff]/.test(q)) layout = "Greek";
    else if (q === "'" && w === ",") layout = "Dvorak";
    else if (semi === "o") layout = "Colemak";
    R.kbd = layout;
    setProbe("kbd", `${layout} 物理布局 (${map.size} 键映射 · Q=${q}, Y=${y}, ;=${semi})`);
  }

  async function probeVoices() {
    if (!window.speechSynthesis) {
      R.voices = [];
      return setNA("voices", "不支持 SpeechSynthesis");
    }
    let list = speechSynthesis.getVoices();
    if (!list.length) {
      await within(new Promise(res => { speechSynthesis.addEventListener("voiceschanged", res, { once: true }); }), 1400, null);
      list = speechSynthesis.getVoices();
    }
    const local = list.filter(v => v.localService);
    const langs = Array.from(new Set((local.length ? local : list).map(v => v.lang).filter(Boolean)));
    R.voices = local.map(v => v.lang).filter(Boolean);
    if (!list.length) return setNA("voices", "无可用语音合成包");
    setProbe("voices", `共 ${list.length} 个语音包 (本地离线 ${local.length} 个) · 语种: ${langs.slice(0, 6).join(", ")}`, {
      why: list.slice(0, 15).map(v => `${v.name} [${v.lang}]${v.localService ? " (本地)" : ""}`).join("\n")
    });
  }

  // 8. Device, OS Anti-Spoof, Screen, Refresh Rate, Engine & Codecs
  function probeDeviceAndSpecs() {
    // True JS engine via error wording
    let engine = "Unknown";
    try { null[0](); } catch (e) {
      const msg = String(e && e.message || "");
      if (/Cannot read propert/i.test(msg)) engine = "V8";
      else if (/null has no properties|can't access property/i.test(msg)) engine = "SpiderMonkey";
      else if (/null is not an object/i.test(msg)) engine = "JavaScriptCore";
    }
    R.engine = engine;
    setProbe("engine", `${engine} 引擎`);

    // JS feature level -> true Chromiumfloor
    let engVer = 0;
    const hitFeats = [];
    for (const [v, name, fn] of JS_FEATURES) {
      let ok = false;
      try { ok = !!fn(); } catch (e) {}
      if (ok) { engVer = v; hitFeats.push(name); }
    }
    R.engVer = engVer;
    setProbe("engver", engVer ? `语法特性达 Chromium ≥ ${engVer} (${hitFeats.slice(-2).join(", ")})` : "基础 ES2020 内核", {
      why: `支持的新特性: ${hitFeats.join(", ")}`
    });

    // CSS feature level
    const CSS_TESTS = [
      [105, "selector(:has(*))"], [111, "color: color-mix(in srgb, red, blue)"], [114, "text-wrap: balance"],
      [117, "transition-behavior: allow-discrete"], [123, "field-sizing: content"], [125, "anchor-name: --a"],
      [129, "interpolate-size: allow-keywords"], [133, "text-box: trim-both cap alphabetic"], [137, "reading-flow: flex-visual"]
    ];
    if (window.CSS && CSS.supports) {
      let cv = 0, miss = null;
      for (const [ver, q] of CSS_TESTS) {
        let ok = false;
        try { ok = CSS.supports(q); } catch (e) {}
        if (ok) cv = ver; else if (miss == null) miss = ver;
      }
      R.cssv = { v: cv, miss };
      setProbe("cssv", cv ? `CSS 渲染特性达 Blink ≥ ${cv}${miss ? ` (缺失 ${miss}+)` : ""}` : "标准 CSS3 引擎");
    } else setNA("cssv");

    // Screen physical resolution
    const dpr = window.devicePixelRatio || 1;
    const [pw, ph] = calcPhysicalScreen(screen.width, screen.height, dpr);
    R.physScreen = `${pw}×${ph}`;
    R.cssScreen = `${screen.width}×${screen.height}`;
    R.dpr = dpr;
    setProbe("screen", `物理 ${pw}×${ph} (CSS ${screen.width}×${screen.height} @ ${+dpr.toFixed(2)}x · ${screen.colorDepth}-bit)`);

    const isExt = screen.isExtended;
    R.multiScreen = !!isExt;
    setProbe("screens", `${isExt == null ? "单屏/未暴露扩展态" : isExt ? "已连接多台显示器 (扩展桌面)" : "单显示器"} · 窗口坐标 (${window.screenX}, ${window.screenY})`);

    const gamut = mq("(color-gamut: rec2020)") ? "Rec.2020 超广色域" : mq("(color-gamut: p3)") ? "Display P3 广色域" : "sRGB 标准色域";
    const hdr = mq("(dynamic-range: high)") ? "HDR 高动态范围" : "SDR";
    setProbe("gamut", `${gamut} · ${hdr}`);

    const tp = navigator.maxTouchPoints || 0;
    const ptr = mq("(pointer: coarse)") ? "手指粗粒度触控" : mq("(pointer: fine)") ? "鼠标/触控板精细指针" : "无指针";
    setProbe("touch", `最大触控点 ${tp} · ${ptr}`);

    setProbe("cpu", navigator.hardwareConcurrency ? `${navigator.hardwareConcurrency} 逻辑核心` : "未暴露");
    setProbe("mem", navigator.deviceMemory ? `≥ ${navigator.deviceMemory} GB (浏览器封顶报 8GB)` : "未暴露 (Safari/Firefox 隐藏)", { na: !navigator.deviceMemory });

    const heapLim = performance.memory?.jsHeapSizeLimit;
    setProbe("heap", heapLim ? `${(heapLim / 1073741824).toFixed(2)} GB V8 堆上限` : "非 Chromium 内核不暴露", { na: !heapLim });

    const cn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (cn) {
      setProbe("conn", [cn.effectiveType?.toUpperCase(), cn.downlink != null ? `下行 ${cn.downlink} Mbps` : "", cn.rtt != null ? `估算 RTT ${cn.rtt} ms` : "", cn.saveData ? "省流开启" : ""].filter(Boolean).join(" · "));
    } else setNA("conn", "NetworkInformation API 未启用");

    // Hardware sensitive APIs surface
    const API_LIST = [
      ["WebUSB", "usb"], ["WebHID", "hid"], ["WebSerial", "serial"], ["WebNFC", "nfc"], ["WebMIDI", "requestMIDIAccess"],
      ["Bluetooth", "bluetooth"], ["WebGPU", "gpu"], ["WebXR", "xr"], ["WakeLock", "wakeLock"],
      ["LocalFonts", "queryLocalFonts"], ["EyeDropper", "EyeDropper", true], ["FileSystem", "showOpenFilePicker", true]
    ];
    const supApis = API_LIST.filter(([, k, onWin]) => k in (onWin ? window : navigator)).map(([n]) => n);
    setProbe("apis", `暴露 ${supApis.length}/${API_LIST.length} 项 (${supApis.slice(0, 6).join(" · ")}${supApis.length > 6 ? "…" : ""})`, {
      why: `全部可用接口: ${supApis.join(", ")}`
    });

    // Emoji font generation probe
    try {
      const ctx = document.createElement("canvas").getContext("2d");
      ctx.font = "24px sans-serif";
      const tofuW = ctx.measureText("\uFFFF").width;
      const EMOJI_VERS = [
        ["Emoji 16.0 (2024–2025 新系统)", "\u{1FAEA}"],
        ["Emoji 15.1 (2023–2024)", "\u{1F426}\u200D\u{1F525}"],
        ["Emoji 15.0 (2022–2023)", "\u{1FA77}"],
        ["Emoji 14.0 (2021–2022)", "\u{1FAE0}"],
        ["Emoji 13.0 (2020)", "\u{1F9CB}"]
      ];
      const hit = EMOJI_VERS.find(([, ch]) => {
        const w = ctx.measureText(ch).width;
        return w > 0 && Math.abs(w - tofuW) > 1 && w < 42;
      });
      setProbe("emoji", hit ? `支持至 ${hit[0]}` : "旧版系统字库 (< Emoji 13.0)");
    } catch (e) { setNA("emoji"); }

    // Video & WebRTC & Recorder codecs
    const vEl = document.createElement("video");
    const canMs = t => { try { return window.MediaSource?.isTypeSupported ? MediaSource.isTypeSupported(t) : !!vEl.canPlayType(t); } catch (e) { return false; } };
    const CODEC_LIST = [
      ["H.264", 'video/mp4; codecs="avc1.42E01E"'], ["VP9", 'video/webm; codecs="vp9"'], ["AV1", 'video/mp4; codecs="av01.0.05M.08"'],
      ["HEVC/H.265", 'video/mp4; codecs="hvc1.1.6.L93.B0"'], ["Dolby Vision", 'video/mp4; codecs="dvh1.05.06"'], ["E-AC-3", 'audio/mp4; codecs="ec-3"']
    ];
    const okCodecs = CODEC_LIST.filter(([, t]) => canMs(t)).map(([n]) => n);
    setProbe("codecs", okCodecs.join(" · ") || "基础解码");

    if (window.RTCRtpSender?.getCapabilities) {
      const ac = RTCRtpSender.getCapabilities("audio")?.codecs || [];
      const vc = RTCRtpSender.getCapabilities("video")?.codecs || [];
      const names = Array.from(new Set([...ac, ...vc].map(c => c.mimeType.split("/")[1]))).filter(x => !/^(rtx|red|ulpfec|flexfec|CN|telephone-event)/i.test(x));
      setProbe("rtccodecs", `视频 ${vc.length} / 音频 ${ac.length} · ${names.join(" ")}`);
    } else setNA("rtccodecs");

    if (window.MediaRecorder?.isTypeSupported) {
      const mimes = ["video/webm;codecs=vp8", "video/webm;codecs=vp9", "video/webm;codecs=av1", "video/webm;codecs=h264", "video/mp4;codecs=avc1", "video/mp4;codecs=hvc1", "video/mp4;codecs=av01", "video/x-matroska;codecs=avc1", "audio/webm;codecs=opus", "audio/mp4;codecs=mp4a.40.2", "audio/ogg;codecs=opus", "audio/mpeg"];
      const okM = mimes.filter(m => { try { return MediaRecorder.isTypeSupported(m); } catch (e) { return false; } });
      setProbe("recmime", `支持 ${okM.length}/${mimes.length} 种封装格式`, { why: okM.join("\n") });
    } else setNA("recmime");
  }

  async function probeHighEntropyHints() {
    let hi = {};
    if (navigator.userAgentData?.getHighEntropyValues) {
      hi = await within(navigator.userAgentData.getHighEntropyValues(["architecture", "bitness", "model", "platform", "platformVersion", "fullVersionList", "wow64"]), 1500, {}) || {};
    }
    R.hi = hi;
    const ua = navigator.userAgent || "";
    const dev = detectDevice(ua, hi, navigator.maxTouchPoints || 0);

    // Anti-spoof Windows version check by exclusive system fonts (Segoe Fluent Icons = Win11, HoloLens MDL2 = Win10)
    if (dev.os === "Windows" && R.sysWinFonts) {
      const f = R.sysWinFonts;
      const realWin = f.includes("Segoe Fluent Icons") ? "11" : f.includes("Segoe MDL2 Assets") ? "10" : f.includes("Segoe UI Emoji") ? "8.1" : f.includes("Segoe UI") ? "7" : null;
      if (realWin && dev.osv === "10/11") dev.osv = realWin;
      else if (realWin && dev.osv && dev.osv !== realWin && +realWin < +dev.osv) {
        R.osFontMismatch = `UA 自称 Windows ${dev.osv}，但系统内置图标字库仅到 Windows ${realWin}`;
      }
    }
    // Safari / Firefox 不支持 UA-CH 且将 macOS UA 永久冻结在 10_15_7，标注为 11+ 以免误导；
    // 而 Chromium (V8) 在 HTTPS 下必然返回真实 platformVersion (12–26+)，若仍停在 10.15 则保留原值交由 fpb 抓伪装！
    if (dev.os === "macOS" && dev.osv === "10.15" && !hi.platformVersion && R.engine && R.engine !== "V8") {
      dev.osv = "11+";
    }
    R.dev = dev;
    const osLabel = [dev.os, dev.osv].filter(Boolean).join(" ") + (dev.model ? ` (${dev.model})` : "");
    R.osLabel = osLabel || navigator.platform || "未知系统";
    setProbe("os", R.osFontMismatch ? `${R.osLabel} (${R.osFontMismatch})` : `${R.osLabel} · platform=${navigator.platform || "–"}`, {
      tone: R.osFontMismatch ? "bad" : "neutral"
    });

    const br = detectBrowser(ua, hi.fullVersionList || navigator.userAgentData?.brands || []);
    R.br = br;
    const brStr = [br.name, br.v].filter(Boolean).join(" ") || "未知浏览器";
    R.browserLabel = brStr;
    setProbe("browser", br.inApp ? `${brStr} (应用内置 WebView 容器)` : brStr);

    if (br.inApp) {
      const banner = $("#inAppBanner");
      if (banner) banner.hidden = false;
    }

    // CPU architecture inference (incl. Apple Silicon via GPU if Safari/Firefox hides UA-CH)
    let arch = hi.architecture || "";
    let bits = hi.bitness || "";
    if (!arch) {
      if (/aarch64|arm64|armv8/i.test(ua)) { arch = "arm"; bits = "64"; }
      else if (/x86_64|Win64|WOW64|amd64/i.test(ua)) { arch = "x86"; bits = "64"; }
      else if (dev.os === "macOS" && /Apple M\d/i.test(R.gpuClean || "")) { arch = "arm (Apple Silicon)"; bits = "64"; }
    }
    R.arch = arch;
    setProbe("arch", [arch || "未直接暴露", bits ? `${bits}-bit` : "", hi.wow64 ? "WOW64" : ""].filter(Boolean).join(" · "));
  }

  async function probeRefreshRate() {
    const deltas = await within(new Promise(resolve => {
      const arr = [];
      let prev = 0;
      function step(ts) {
        if (prev > 0) arr.push(ts - prev);
        prev = ts;
        if (arr.length < 36) requestAnimationFrame(step);
        else resolve(arr);
      }
      requestAnimationFrame(step);
    }), 1600, []);
    if (deltas.length < 8) {
      R.hz = 60;
      return setNA("hz", "后台标签页帧率受限");
    }
    const sorted = deltas.slice(3).sort((a, b) => a - b);
    const med = sorted[Math.floor(sorted.length / 2)] || 16.67;
    const rawHz = 1000 / med;
    const std = [30, 60, 75, 90, 120, 144, 165, 240, 360].reduce((best, h) => Math.abs(h - rawHz) < Math.abs(best - rawHz) ? h : best, 60);
    R.hz = std;
    setProbe("hz", `${std} Hz (帧间隔中位数 ${med.toFixed(2)} ms)`);
  }

  // 9. Graphics: WebGL Dual-Context, Shader Readback, WebGPU Dual-Adapter & Limits (6 items: gpu, glx, webgpu, gpulim, webgl, glimg)
  async function probeGraphics() {
    const readGl = powerPreference => {
      try {
        const cv = document.createElement("canvas");
        const gl = cv.getContext("webgl2", { powerPreference }) || cv.getContext("webgl", { powerPreference });
        if (!gl) return null;
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
        const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
        const ver = gl.getParameter(gl.VERSION);
        const maxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);
        const maxVp = gl.getParameter(gl.MAX_VIEWPORT_DIMS);
        const exts = (gl.getSupportedExtensions() || []).slice().sort();
        const lose = gl.getExtension("WEBGL_lose_context");
        if (lose) lose.loseContext();
        return { vendor: String(vendor || ""), renderer: String(renderer || ""), ver, maxTex, maxVp: Array.from(maxVp || []), exts, isGl2: typeof WebGL2RenderingContext !== "undefined" && gl instanceof WebGL2RenderingContext };
      } catch (e) { return null; }
    };

    const gDef = readGl("default");
    const gHi = readGl("high-performance");

    // WebGPU Dual Adapter (low-power + high-performance)
    let wgpuHi = null, wgpuLo = null, wgpuLimHash = null, wgpuFeatCnt = 0, wgpuFeats = [];
    if (navigator.gpu?.requestAdapter) {
      const getAdp = async pref => {
        const adp = await within(navigator.gpu.requestAdapter({ powerPreference: pref }), 1800, null);
        if (!adp) return null;
        const info = adp.info || (adp.requestAdapterInfo ? await within(adp.requestAdapterInfo(), 1000, {}) : {});
        return { adp, vendor: info.vendor || "", architecture: info.architecture || "", device: info.device || "", description: info.description || "" };
      };
      [wgpuLo, wgpuHi] = await Promise.all([getAdp("low-power"), getAdp("high-performance")]);
      const mainAdp = (wgpuHi || wgpuLo)?.adp;
      if (mainAdp) {
        const lims = [];
        for (const k in mainAdp.limits) lims.push(`${k}=${mainAdp.limits[k]}`);
        wgpuFeats = Array.from(mainAdp.features || []).sort();
        wgpuFeatCnt = wgpuFeats.length;
        wgpuLimHash = shortHash(await sha256(lims.sort().join(",") + "|" + wgpuFeats.join(",")));
      }
    }

    if (gDef) {
      const clean = cleanGpuName(gDef.renderer) || gDef.renderer;
      const cleanHi = gHi ? (cleanGpuName(gHi.renderer) || gHi.renderer) : null;
      const dgpu = findDiscreteGpu(clean, cleanHi, wgpuHi, wgpuLo);
      const soft = isSoftGpu(gDef.renderer);
      R.gpuRaw = gDef.renderer;
      R.gpuVendor = gDef.vendor;
      R.gpuClean = clean;
      R.gpuDiscrete = dgpu;
      R.gpuSoft = soft;

      setProbe("gpu", dgpu ? `双显卡：${dgpu} (独显) + ${clean} (核显)` : soft ? `虚拟机/软件渲染 (${gDef.renderer})` : clean, {
        tone: soft ? "bad" : "neutral",
        why: `原始渲染器: ${gDef.renderer}\nVendor: ${gDef.vendor}`
      });
      setProbe("glx", `${gDef.isGl2 ? "WebGL 2.0" : "WebGL 1.0"} · 最大纹理 ${gDef.maxTex}px · ${gDef.exts.length} 个扩展`, {
        why: gDef.exts.join(" · ")
      });
      const glParamHash = shortHash(await sha256([gDef.vendor, gDef.renderer, gDef.maxTex, gDef.maxVp.join("x"), gDef.exts.join(",")].join("|")));
      R.webglHash = glParamHash;
      setProbe("webgl", `${glParamHash} (${gDef.exts.length} 项驱动参数与扩展)`);
    } else {
      setNA("gpu", "WebGL 已禁用");
      setNA("glx", "WebGL 已禁用");
      setNA("webgl", "WebGL 已禁用");
    }

    // WebGL Shader Pixel Readback Fingerprint
    try {
      const cv = document.createElement("canvas");
      cv.width = cv.height = 64;
      const gl = cv.getContext("webgl", { preserveDrawingBuffer: true });
      if (gl) {
        const mk = (t, s) => { const sh = gl.createShader(t); gl.shaderSource(sh, s); gl.compileShader(sh); return sh; };
        const prg = gl.createProgram();
        gl.attachShader(prg, mk(gl.VERTEX_SHADER, "attribute vec2 a;varying vec2 v;void main(){v=a;gl_Position=vec4(a,0.,1.);}"));
        gl.attachShader(prg, mk(gl.FRAGMENT_SHADER, "precision mediump float;varying vec2 v;void main(){gl_FragColor=vec4(sin(v.x*9.7)*.5+.5,cos(v.y*7.3)*.5+.5,fract(v.x*v.y*37.1),1.);}"));
        gl.linkProgram(prg); gl.useProgram(prg);
        gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.9, -0.8, 0.85, -0.7, -0.1, 0.95]), gl.STATIC_DRAW);
        const loc = gl.getAttribLocation(prg, "a");
        gl.enableVertexAttribArray(loc);
        gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
        const px = new Uint8Array(64 * 64 * 4);
        gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, px);
        gl.getExtension("WEBGL_lose_context")?.loseContext();
        setProbe("glimg", shortHash(await sha256(px.join(","))));
      } else setNA("glimg");
    } catch (e) { setNA("glimg"); }

    // WebGPU display
    if (wgpuHi || wgpuLo) {
      const fmtW = x => x ? [x.vendor, x.architecture, x.description || x.device].filter(Boolean).join(" / ") : "";
      const sHi = fmtW(wgpuHi), sLo = fmtW(wgpuLo);
      setProbe("webgpu", sHi && sLo && sHi !== sLo ? `高性能 [${sHi}] · 低功耗 [${sLo}]` : (sHi || sLo || "已启用 WebGPU (匿名适配器)"));
      setProbe("gpulim", `${wgpuLimHash} (${wgpuFeatCnt} 项硬件 Feature)`, { why: wgpuFeats.join(" · ") });
    } else {
      setNA("webgpu", "未启用或不支持 WebGPU");
      setNA("gpulim", "未启用 WebGPU");
    }
  }

  // 10. Audio Hardware, OfflineAudio Fingerprint & ConstantSource Noise Trap (3 items: audiohw, audio, aunoise)
  async function probeAudioStack() {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (AC) {
      try {
        const ctx = new AC();
        const sr = ctx.sampleRate;
        const ch = ctx.destination?.maxChannelCount || 2;
        const lat = ctx.baseLatency != null ? ` · 基础延迟 ${(ctx.baseLatency * 1000).toFixed(1)}ms` : "";
        ctx.close().catch(() => {});
        setProbe("audiohw", `${sr} Hz · 最大 ${ch} 声道${lat}`);
      } catch (e) { setNA("audiohw"); }
    } else setNA("audiohw");

    const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!OAC) {
      setNA("audio");
      setNA("aunoise");
      return;
    }

    // Compressor Audio Fingerprint
    try {
      const ctx = new OAC(1, 5000, 44100);
      const osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.value = 10000;
      const cmp = ctx.createDynamicsCompressor();
      cmp.threshold.value = -50; cmp.knee.value = 40; cmp.ratio.value = 12; cmp.attack.value = 0; cmp.release.value = 0.25;
      osc.connect(cmp); cmp.connect(ctx.destination);
      osc.start(0);
      const buf = await within(ctx.startRendering(), 1800, null);
      if (buf) {
        const ch = buf.getChannelData(0);
        let sum = 0;
        for (let i = 4500; i < 5000; i++) sum += Math.abs(ch[i]);
        const h = shortHash(await sha256(sum.toFixed(12)));
        R.audioHash = h;
        setProbe("audio", `${h} (压缩采样和 ${sum.toFixed(6)})`);
      } else setNA("audio");
    } catch (e) { setNA("audio"); }

    // ConstantSourceNode(0.5) Anti-Fingerprint Noise Trap
    try {
      const ctx = new OAC(1, 256, 44100);
      if (ctx.createConstantSource) {
        const src = ctx.createConstantSource();
        src.offset.value = 0.5;
        src.connect(ctx.destination);
        src.start();
        const buf = await within(ctx.startRendering(), 1500, null);
        if (buf) {
          const d = buf.getChannelData(0);
          let maxDiff = 0;
          for (let i = 0; i < d.length; i++) maxDiff = Math.max(maxDiff, Math.abs(d[i] - 0.5));
          R.auNoise = maxDiff > 1e-7;
          setProbe("aunoise", R.auNoise ? `检出音频加噪篡改！(恒定 0.5 源偏移 ${maxDiff.toExponential(2)})` : "纯净无篡改 (256 采样精确恒等于 0.5)", {
            tone: R.auNoise ? "warn" : "ok"
          });
        } else setNA("aunoise");
      } else setNA("aunoise");
    } catch (e) { setNA("aunoise"); }
  }

  // 11. Async Hardware: Battery, Media Devices, HW Video Decode, DRM, Biometrics, Bluetooth, Storage (7 items)
  async function probeAsyncHardware() {
    // Battery
    const pBat = (async () => {
      if (!navigator.getBattery) return setNA("battery", "非 Chromium 内核已屏蔽电池接口");
      const b = await within(navigator.getBattery(), 1500, null);
      if (!b) return setNA("battery");
      const pct = Math.round(b.level * 100);
      const isDesktopAc = b.charging && b.level === 1 && b.chargingTime === 0 && b.dischargingTime === Infinity;
      R.powerState = isDesktopAc ? "ac" : `${b.charging ? "c" : "b"}${pct}`;
      setProbe("battery", isDesktopAc ? "外接交流电源满电 (典型台式机/常插电模式)" : `${pct}% · ${b.charging ? "正在充电" : "电池供电"}`);
    })();

    // Media devices count
    const pMedia = (async () => {
      if (!navigator.mediaDevices?.enumerateDevices) return setNA("media");
      const list = await within(navigator.mediaDevices.enumerateDevices(), 1500, []);
      const cam = list.filter(d => d.kind === "videoinput").length;
      const mic = list.filter(d => d.kind === "audioinput").length;
      const spk = list.filter(d => d.kind === "audiooutput").length;
      setProbe("media", `摄像头 ${cam} · 麦克风 ${mic} · 扬声器/耳机 ${spk}`);
    })();

    // Hardware efficient video decode
    const pHwDec = (async () => {
      if (!navigator.mediaCapabilities?.decodingInfo) return setNA("hwdec");
      const types = [
        ["H.264", 'video/mp4; codecs="avc1.640028"'],
        ["HEVC/H.265", 'video/mp4; codecs="hvc1.1.6.L120.90"'],
        ["VP9", 'video/webm; codecs="vp09.00.41.08"'],
        ["AV1", 'video/mp4; codecs="av01.0.08M.08"']
      ];
      const res = await Promise.all(types.map(([n, contentType]) =>
        within(navigator.mediaCapabilities.decodingInfo({
          type: "file",
          video: { contentType, width: 1920, height: 1080, bitrate: 8000000, framerate: 60 }
        }).then(r => r?.powerEfficient ? n : null, () => null), 1500, null)
      ));
      const hw = res.filter(Boolean);
      R.hwCodecs = hw;
      setProbe("hwdec", hw.length ? `芯片硬解: ${hw.join(" · ")}` : "纯软件解码或未暴露硬解状态");
    })();

    // DRM (skip Firefox prompt)
    const pDrm = (async () => {
      if (!navigator.requestMediaKeySystemAccess || /Firefox\//.test(navigator.userAgent)) return setNA("drm", "当前内核免打扰跳过或不支持");
      const cfg = [{ initDataTypes: ["cenc"], videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.42E01E"' }] }];
      const sys = [["Widevine", "com.widevine.alpha"], ["FairPlay", "com.apple.fps"], ["PlayReady", "com.microsoft.playready.recommendation"], ["ClearKey", "org.w3.clearkey"]];
      const r = await Promise.all(sys.map(([n, ks]) => within(navigator.requestMediaKeySystemAccess(ks, cfg).then(() => n, () => null), 1800, null)));
      const ok = r.filter(Boolean);
      setProbe("drm", ok.length ? ok.join(" · ") : "未启用 DRM 模块");
    })();

    // Biometrics
    const pBio = (async () => {
      const fn = window.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable;
      if (!fn) return setNA("bio");
      const ok = await within(fn.call(PublicKeyCredential), 1500, null);
      setProbe("bio", ok ? "已配备平台生物识别硬件 (Touch ID / Windows Hello / Face ID)" : "未检出内置生物识别模块");
    })();

    // Bluetooth
    const pBt = (async () => {
      if (!navigator.bluetooth?.getAvailability) return setNA("bt", "非 Chromium 内核未开放 WebBluetooth");
      const ok = await within(navigator.bluetooth.getAvailability(), 1500, null);
      setProbe("bt", ok ? "本机蓝牙硬件可用" : "无蓝牙模块或已关闭");
    })();

    // Storage quota
    const pSto = (async () => {
      if (!navigator.storage?.estimate) return setNA("storage");
      const est = await within(navigator.storage.estimate(), 1500, null);
      if (!est?.quota) return setNA("storage");
      const gb = est.quota / 1073741824;
      setProbe("storage", gb >= 1 ? `站点配额 ${gb.toFixed(1)} GB` : `站点配额 ${Math.round(est.quota / 1048576)} MB`);
    })();

    await Promise.all([pBat, pMedia, pHwDec, pDrm, pBio, pBt, pSto]);
  }


  // 12. Browser Preferences, Anti-Automation, AdBlock, Extensions, Worker, iframe & 52-API Lies
  function probeNavAndPrefs() {
    const ref = document.referrer || "";
    const navEntry = performance.getEntriesByType("navigation")[0];
    setProbe("h_ref", ref ? `${ref} (${navEntry?.type || "navigate"})` : `直接访问 / 无 Referer (${navEntry?.type || "navigate"})`);

    const isDarkSys = mq("(prefers-color-scheme: dark)");
    R.sysDark = isDarkSys;
    setProbe("scheme", `${isDarkSys ? "系统偏好深色模式 (Dark)" : "系统偏好浅色模式 (Light)"}${mq("(prefers-contrast: more)") ? " · 高对比度" : ""}`);

    // Default font size & OS AccentColor
    try {
      const d = document.createElement("div");
      d.style.cssText = "position:absolute;left:-9999px;font-size:1rem;color:AccentColor";
      document.body.appendChild(d);
      const cs = getComputedStyle(d);
      const fs = parseFloat(cs.fontSize) || 16;
      const ac = cs.color || "";
      d.remove();
      R.baseFontPx = fs;
      setProbe("sysui", `基础字号 ${fs}px · 系统强调色 ${ac}`);
    } catch (e) { setNA("sysui"); }

    // Scrollbar physical width
    try {
      const d = document.createElement("div");
      d.style.cssText = "position:absolute;top:-9999px;left:0;width:100px;height:100px;overflow:scroll;scrollbar-width:auto";
      document.body.appendChild(d);
      const sbw = d.offsetWidth - d.clientWidth;
      d.remove();
      R.scrollbarW = sbw;
      setProbe("scrollbar", sbw > 0 ? `${sbw}px 经典占位滚动条 (Windows/Linux 常见)` : "0px 悬浮式滚动条 (macOS/移动端特征)");
    } catch (e) { setNA("scrollbar"); }

    // Font antialiasing mode
    try {
      const c = document.createElement("canvas");
      c.width = 140; c.height = 30;
      const x = c.getContext("2d", { alpha: false });
      x.fillStyle = "#fff"; x.fillRect(0, 0, 140, 30);
      x.fillStyle = "#000"; x.font = "16px sans-serif"; x.fillText("Wwg ii 你好 Ma", 2, 21);
      const px = x.getImageData(0, 0, 140, 30).data;
      let gray = 0, sub = 0;
      for (let i = 0; i < px.length; i += 4) {
        const r = px[i], g = px[i + 1], b = px[i + 2];
        if (Math.max(Math.abs(r - g), Math.abs(g - b), Math.abs(r - b)) > 8) sub++;
        else if (r > 0 && r < 255) gray++;
      }
      R.subpixelMode = sub > 10 ? "rgb" : gray > 10 ? "gray" : "none";
      setProbe("smooth", sub > 10 ? "RGB 亚像素抗锯齿 (ClearType 风格)" : gray > 10 ? "灰度平滑抗锯齿 (macOS/Retina 风格)" : "未开启抗锯齿");
    } catch (e) { setNA("smooth"); }

    const rm = mq("(prefers-reduced-motion: reduce)");
    R.reducedMotion = rm;
    setProbe("motion", rm ? "已开启减弱动态效果" : "标准动画 (未减弱)");

    const a11yFlags = [
      ["(prefers-contrast: more)", "增强对比度"],
      ["(forced-colors: active)", "强制高对比色彩"],
      ["(prefers-reduced-transparency: reduce)", "减少透明度"],
      ["(inverted-colors: inverted)", "反色模式"],
      ["(prefers-reduced-data: reduce)", "省流量模式"]
    ].filter(([q]) => mq(q)).map(([, n]) => n);
    setProbe("a11y", a11yFlags.length ? a11yFlags.join(" · ") : "默认（无特殊视觉辅助开关）");

    const dm = ["fullscreen", "standalone", "minimal-ui"].find(m => mq(`(display-mode: ${m})`));
    setProbe("display", dm === "fullscreen" ? "全屏模式" : dm ? "独立 PWA 应用窗口" : "标准浏览器标签页");

    const barH = Math.max(0, screen.height - screen.availHeight);
    const barW = Math.max(0, screen.width - screen.availWidth);
    setProbe("win", `视口 ${window.innerWidth}×${window.innerHeight} · 系统栏占用 高 ${barH}px / 宽 ${barW}px`);

    const dnt = navigator.doNotTrack === "1" || window.doNotTrack === "1";
    const gpc = !!navigator.globalPrivacyControl;
    setProbe("dnt", `DNT: ${dnt ? "已开启" : "未开"} · GPC: ${gpc ? "已开启" : "未开"}`);

    setProbe("cookies", navigator.cookieEnabled ? "已允许读写 Cookie" : "Cookie 已禁用", { tone: navigator.cookieEnabled ? "neutral" : "warn" });
    setProbe("pdf", navigator.pdfViewerEnabled != null ? (navigator.pdfViewerEnabled ? "内置 PDF 查看器已启用" : "未启用 PDF 查看器") : "未暴露");
    setProbe("history", `当前会话栈 ${window.history.length} 页`);

    // Automation & WebDriver markers
    const autoHits = [];
    if (navigator.webdriver) autoHits.push("navigator.webdriver=true");
    if (Object.keys(window).some(k => /^cdc_|^\$cdc_/.test(k)) || Object.keys(document).some(k => /^\$cdc_|^__webdriver|^__selenium/.test(k))) autoHits.push("ChromeDriver($cdc_)");
    if (window.__playwright || window.__pwInitScripts) autoHits.push("Playwright");
    if (window._phantom || window.callPhantom) autoHits.push("PhantomJS");
    if (/HeadlessChrome|PhantomJS|SlimerJS/i.test(navigator.userAgent)) autoHits.push("Headless UA");
    R.botHits = autoHits;
    setProbe("webdriver", autoHits.length ? `检出自动化控制痕迹：${autoHits.join(" · ")}` : "未检出自动化框架钩子 (真人交互环境)", {
      tone: autoHits.length ? "bad" : "ok"
    });
  }

  async function probePermissions() {
    if (!navigator.permissions?.query) return setNA("perms");
    const items = [["geolocation", "定位"], ["notifications", "通知"], ["camera", "摄像头"], ["microphone", "麦克风"]];
    const stateLabel = { granted: "已允许", denied: "已拒绝", prompt: "询问" };
    const res = await Promise.all(items.map(([name, zh]) =>
      within(navigator.permissions.query({ name }).then(s => `${zh}:${stateLabel[s.state] || s.state}`, () => null), 1200, null)
    ));
    const ok = res.filter(Boolean);
    setProbe("perms", ok.length ? ok.join(" · ") : "未暴露权限状态");
  }

  // Dual AdBlock test: DOM cosmetic bait + Google adsbygoogle.js vs generate_204 network comparison
  async function probeAdblock() {
    await new Promise(r => setTimeout(r, 150));
    const el = $("#ad-slot");
    const cs = el ? getComputedStyle(el) : null;
    const domHidden = !el || el.offsetHeight === 0 || cs.display === "none" || cs.visibility === "hidden";

    let netBlocked = false;
    if (!domHidden) {
      const checkUrl = u => within(fetch(u, { method: "HEAD", mode: "no-cors", cache: "no-store", credentials: "omit" }).then(() => true, () => false), 3000, null);
      const [adOk, gOk] = await Promise.all([
        checkUrl("https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"),
        checkUrl("https://www.google.com/generate_204")
      ]);
      netBlocked = adOk === false && gOk === true;
    }
    R.adblock = domHidden || netBlocked;
    R.adblockKind = domHidden ? "DOM 样式规则隐藏" : netBlocked ? "网络层请求拦截 (MV3/DNS)" : null;
    setProbe("adblock", domHidden ? "已启用广告拦截（元素隐藏规则命中）" : netBlocked ? "已启用广告拦截（广告域名网络请求被阻断）" : "未检测到广告拦截器", {
      tone: R.adblock ? "ok" : "neutral"
    });
  }

  // DOM-injected extensions detection
  async function probeDomExtensions() {
    await new Promise(r => setTimeout(r, 950));
    const w = window, d = document.documentElement, b = document.body;
    const hasSel = s => { try { return !!document.querySelector(s); } catch (e) { return false; } };
    const hits = [];
    const eth = w.ethereum;
    if (eth) {
      hits.push(["crypto", eth.isRabby ? "Rabby Wallet" : eth.isOkxWallet || w.okxwallet ? "OKX Wallet" : eth.isCoinbaseWallet ? "Coinbase Wallet" : eth.isBraveWallet ? "Brave Wallet" : eth.isTrust ? "Trust Wallet" : eth.isTokenPocket ? "TokenPocket" : eth.isMetaMask ? "MetaMask" : "EVM 钱包插件"]);
    } else if (w.okxwallet) hits.push(["crypto", "OKX Wallet"]);
    if (w.phantom || w.solana?.isPhantom) hits.push(["crypto", "Phantom"]);
    if (w.tronLink || w.tronWeb) hits.push(["crypto", "TronLink"]);
    if (w.keplr) hits.push(["crypto", "Keplr"]);
    if (w.bitkeep) hits.push(["crypto", "Bitget Wallet"]);
    if (w.__REACT_DEVTOOLS_GLOBAL_HOOK__) hits.push(["dev", "React DevTools"]);
    if (w.__VUE_DEVTOOLS_GLOBAL_HOOK__) hits.push(["dev", "Vue DevTools"]);
    if (w.__REDUX_DEVTOOLS_EXTENSION__) hits.push(["dev", "Redux DevTools"]);
    if (b?.hasAttribute("data-gr-ext-installed") || b?.hasAttribute("data-new-gr-c-s-check-loaded")) hits.push(["tool", "Grammarly"]);
    if (d.hasAttribute("data-darkreader-mode") || d.hasAttribute("data-darkreader-scheme") || hasSel('meta[name="darkreader"]')) hits.push(["tool", "Dark Reader"]);
    if (hasSel('[id*="immersive-translate"],[class*="immersive-translate"]') || d.hasAttribute("imt-state")) hits.push(["tool", "沉浸式翻译 (Immersive Translate)"]);
    if (d.classList.contains("translated-ltr") || d.classList.contains("translated-rtl")) hits.push(["tool", "Google 网页翻译"]);
    if (hasSel("#loom-companion-mv3")) hits.push(["tool", "Loom"]);
    if (hasSel('script[src*="kaspersky-labs"],link[href*="kaspersky-labs"]')) hits.push(["sec", "Kaspersky 网页注入"]);

    R.domExts = hits;
    setProbe("ext", hits.length ? hits.map(x => x[1]).join(" · ") : "未发现向页面直接注入全局变量的扩展");
  }

  // 36 Popular Proxy, Anti-Detect, Wallet & Security Chrome Extensions WAR Scan
  const CHROME_EXT_WAR = [
    ["uBlock Origin", "cjpalhdlnbpafiamejdnhcphjbkeiagm", ["web_accessible_resources/noop.html"]],
    ["uBlock Origin Lite", "ddkjiahejlhfcafbddmgiahcphecmpfh", ["web_accessible_resources/noop.js"]],
    ["AdGuard", "bgnkhhnnamicmpeenaelnjfhikgbkllg", ["web-accessible-resources/redirects/noopjs.js"]],
    ["AdBlock", "gighmmpiobklfepjocnamgkkbiglidom", ["icons/icon24.png"]],
    ["Adblock Plus", "cfhdojbkjhnklbpkdaibdccddilifddb", ["icons/abp-16.png"]],
    ["Ghostery", "mlomiejdfkolichcflejclcbmpeaniij", ["app/templates/trackers-preview.html"]],
    ["Privacy Badger", "pkehgijcmpdhfbdbbnkijodmdjhbjlgp", ["data/web_accessible_resources/noop.js"]],
    ["Decentraleyes", "ldpochfccmkkmhdbclfhpagapcfdljkj", ["resources/webfont/1.6.28/webfont.js"]],
    ["Proxy SwitchyOmega", "padekgcemlokbadohgkifijomclgjgif", ["img/icons/omega-48.png"]],
    ["ZeroOmega", "pfnededegaaopdmhkdmcofjmoldfiped", ["img/icons/omega-48.png"]],
    ["User-Agent Switcher", "djflhoibgkdhkhhcedjiklpkjnoahfmg", ["js/inject.js", "icon_128.png"]],
    ["CanvasBlocker / Defender", "nomnklagbgmgghhjidfhnoelnjfndfpd", ["data/inject/isolated.js"]],
    ["WebRTC Network Limiter", "npeicpdbkakmehahjeeohfdhnlpdklia", ["icon128.png"]],
    ["WebRTC Leak Prevent", "eiadekoaikejlgdbkbdfeijglgfdalml", ["img/icon48.png"]],
    ["ModHeader", "idgpnmonknjnojddfkpgkljpfnnfcklj", ["images/icon.png"]],
    ["Header Editor", "eningockdidmgiojffjmkdblpjocbhgh", ["assets/images/128.png"]],
    ["Cookie-Editor", "hlkenndednhfkekhgcdicdfddnkalmdm", ["icons/cookie-48.png"]],
    ["EditThisCookie", "fngmhnnpilhplaeedifhccceomclgfbg", ["img/icon_48x48.png"]],
    ["Tampermonkey 篡改猴", "dhdgffkkebhmkfjojejmpbldmpobfkfo", ["images/icon.png"]],
    ["Violentmonkey 暴力猴", "jinjaccalgkegednnccohejagnlnfdag", ["public/images/icon48.png"]],
    ["Stylus", "clngdbkpkpeebahjckkjfobafhncgmne", ["images/icon/48.png"]],
    ["沉浸式翻译", "bpoadfkcbjbfhfodiogcnhhhpibjhbnh", ["styles/inject.css"]],
    ["Google 翻译", "aapbdbdomjkkjkaonfhkkikfgjllcleb", ["popup_css_compiled.css"]],
    ["DeepL 翻译", "cofdbpoegempjloogbagkncekinflcnj", ["images/deepl-logo.svg"]],
    ["MetaMask", "nkbihfbeogaeaoehlefnkodbefgpgknn", ["scripts/inpage.js", "inpage.js"]],
    ["Rabby Wallet", "acmacodkjbdgmoleebolmdjonilkdbch", ["pageProvider.js"]],
    ["OKX Wallet", "mcohilncbfahbmgdjkbpemcciiolgcge", ["scripts/lib/inpage.js"]],
    ["Phantom", "bfnaelmomeimhlpmgjnjophhpkkoljpa", ["injected.js"]],
    ["Coinbase Wallet", "hnfanknocfeofbddgcijnmhnfnkdnaad", ["requestProvider.js"]],
    ["Trust Wallet", "egjidjbpglichdcondbcbdnbeeppgdph", ["inpage.js"]],
    ["Bitget Wallet", "jiidiaalihmmhddjgbnbgdfflelocpak", ["inpage.js"]],
    ["1Password", "aeblfdkhhhdcdjpifhhbdiojplfjncoa", ["inline/injected.js"]],
    ["Bitwarden", "nngceckbapebfimnlniiiahkandclblb", ["notification/bar.html", "overlay/menu-list.html"]],
    ["LastPass", "hdokiejnpimakedhajhdlcegeplioahd", ["overlay.html", "images/icon48.png"]],
    ["Wappalyzer", "gppongmhjkpfnbhagpmjfkannfbllamg", ["images/icons/default.svg"]],
    ["ColorZilla", "bhlhnicpbhignbdhedgjhgdocnmhomnp", ["html/content-script-iframe.html"]]
  ];

  async function probeChromeExtWar() {
    if (R.engine !== "V8" || /Firefox/.test(navigator.userAgent)) {
      R.extWar = [];
      return setNA("extwar", "仅适用于 Chromium 系扩展协议");
    }
    const hits = await Promise.all(CHROME_EXT_WAR.map(async ([name, id, files]) => {
      for (const f of files) {
        const ok = await within(fetch(`chrome-extension://${id}/${f}`, { cache: "no-store" }).then(r => r.ok, () => false), 1200, false);
        if (ok) return name;
      }
      return null;
    }));
    const found = hits.filter(Boolean);
    R.extWar = found;
    setProbe("extwar", found.length ? `命中 ${found.length} 款：${found.join(" · ")}` : `扫描 ${CHROME_EXT_WAR.length} 款常见扩展均未暴露公开资源`, {
      tone: found.length ? "warn" : "neutral"
    });
  }

  // Web Worker independent thread verification
  async function probeWorkerRealm() {
    if (!window.Worker || !window.Blob) {
      R.workerDiff = [];
      return setNA("worker");
    }
    const code = `
      try {
        postMessage({
          ua: navigator.userAgent,
          plat: navigator.platform,
          langs: (navigator.languages || []).join(","),
          hc: navigator.hardwareConcurrency,
          mem: navigator.deviceMemory || null,
          tz: Intl.DateTimeFormat().resolvedOptions().timeZone
        });
      } catch (e) { postMessage(null); }
    `;
    const blobUrl = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
    let wk = null;
    try { wk = new Worker(blobUrl); } catch (e) {
      URL.revokeObjectURL(blobUrl);
      R.workerDiff = [];
      return setNA("worker", "CSP 或沙箱限制创建 Worker");
    }
    const wData = await within(new Promise(res => {
      wk.onmessage = e => res(e.data);
      wk.onerror = () => res(null);
    }), 1800, null);
    wk.terminate();
    URL.revokeObjectURL(blobUrl);

    if (!wData) {
      R.workerDiff = [];
      return setNA("worker", "Worker 未返回读数");
    }
    const main = {
      ua: navigator.userAgent,
      plat: navigator.platform,
      langs: (navigator.languages || []).join(","),
      hc: navigator.hardwareConcurrency,
      mem: navigator.deviceMemory || null,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
    const labels = { ua: "userAgent", plat: "platform", langs: "languages", hc: "CPU核数", mem: "内存", tz: "时区" };
    const diffs = Object.keys(main).filter(k => wData[k] != null && String(wData[k]) !== "" && String(wData[k]) !== String(main[k]));
    R.workerDiff = diffs;
    setProbe("worker", diffs.length ? `跨线程矛盾！Worker 与主页面不一致: ${diffs.map(k => labels[k]).join(", ")}` : "主页面与独立 Worker 线程完全一致", {
      tone: diffs.length ? "bad" : "ok",
      why: diffs.length ? diffs.map(k => `主线程 ${labels[k]}: ${main[k]}\nWorker ${labels[k]}: ${wData[k]}`).join("\n") : ""
    });
  }

  // 52 Native Getters/Methods Prototype Lie Detector + Clean iframe Sandbox Diff
  const LIE_GETTERS = [
    ["Navigator", ["userAgent", "appVersion", "platform", "vendor", "language", "languages", "hardwareConcurrency", "deviceMemory", "maxTouchPoints", "webdriver", "plugins", "mimeTypes", "userAgentData", "connection", "doNotTrack", "pdfViewerEnabled"]],
    ["Screen", ["width", "height", "availWidth", "availHeight", "colorDepth", "pixelDepth"]],
    ["HTMLElement", ["offsetWidth", "offsetHeight"]]
  ];
  const LIE_METHODS = [
    ["HTMLCanvasElement", ["toDataURL", "toBlob", "getContext"]],
    ["CanvasRenderingContext2D", ["getImageData", "measureText", "fillText", "isPointInPath"]],
    ["WebGLRenderingContext", ["getParameter", "getExtension", "getSupportedExtensions", "readPixels", "getShaderPrecisionFormat"]],
    ["WebGL2RenderingContext", ["getParameter", "readPixels"]],
    ["AudioBuffer", ["getChannelData", "copyFromChannel"]],
    ["AnalyserNode", ["getFloatFrequencyData"]],
    ["OfflineAudioContext", ["startRendering"]],
    ["Date", ["getTimezoneOffset", "toString"]],
    ["Element", ["getBoundingClientRect", "getClientRects"]],
    ["Range", ["getBoundingClientRect", "getClientRects"]],
    ["Navigator", ["getBattery", "sendBeacon"]],
    ["MediaDevices", ["enumerateDevices"]],
    ["Permissions", ["query"]],
    ["Function", ["toString"]],
    ["Math", ["random"]]
  ];

  function probeLiesAndIframe() {
    const fr = document.createElement("iframe");
    fr.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden;pointer-events:none";
    fr.setAttribute("aria-hidden", "true");
    fr.tabIndex = -1;
    document.body.appendChild(fr);

    const w = fr.contentWindow;
    const cleanToString = (w && w.Function?.prototype?.toString) || Function.prototype.toString;
    const isNativeSrc = fn => {
      try { return /\{\s*\[native code\]\s*\}\s*$/.test(cleanToString.call(fn)); } catch (e) { return false; }
    };

    const lies = [];
    let testedCount = 0;

    const inspectFn = (label, fn, protoOwner) => {
      if (typeof fn !== "function") return;
      let hooked = !isNativeSrc(fn) || Object.prototype.hasOwnProperty.call(fn, "prototype");
      if (!hooked && protoOwner) {
        try {
          fn.call(Object.create(protoOwner));
          hooked = true;
        } catch (e) {
          hooked = !(e instanceof TypeError) && !(w && e instanceof w.TypeError);
        }
      }
      if (hooked) lies.push(label);
    };

    for (const [cls, props] of LIE_GETTERS) {
      const proto = window[cls]?.prototype;
      if (!proto) continue;
      for (const k of props) {
        const d = Object.getOwnPropertyDescriptor(proto, k);
        if (d?.get) { testedCount++; inspectFn(`${cls}.${k}`, d.get, proto); }
      }
    }
    for (const [cls, methods] of LIE_METHODS) {
      const obj = cls === "Math" ? Math : window[cls]?.prototype;
      if (!obj) continue;
      for (const k of methods) {
        const d = Object.getOwnPropertyDescriptor(obj, k);
        if (d && typeof d.value === "function") { testedCount++; inspectFn(`${cls}.${k}`, d.value, null); }
      }
    }

    // Own-property overrides directly on navigator / screen instances
    for (const [inst, nm] of [[navigator, "navigator"], [screen, "screen"]]) {
      for (const k of Object.getOwnPropertyNames(inst)) {
        lies.push(`${nm}.${k}(实例覆写)`);
      }
    }

    // Clean iframe value comparison
    const frameDiffs = [];
    try {
      if (w && w.navigator && w.screen && w.Intl) {
        const cmp = (name, a, b) => { if (String(a) !== String(b)) frameDiffs.push(name); };
        cmp("userAgent", navigator.userAgent, w.navigator.userAgent);
        cmp("platform", navigator.platform, w.navigator.platform);
        cmp("languages", navigator.languages, w.navigator.languages);
        cmp("hardwareConcurrency", navigator.hardwareConcurrency, w.navigator.hardwareConcurrency);
        cmp("deviceMemory", navigator.deviceMemory, w.navigator.deviceMemory);
        cmp("screen", `${screen.width}x${screen.height}`, `${w.screen.width}x${w.screen.height}`);
        cmp("timeZone", Intl.DateTimeFormat().resolvedOptions().timeZone, w.Intl.DateTimeFormat().resolvedOptions().timeZone);
        cmp("timezoneOffset", new Date().getTimezoneOffset(), new w.Date().getTimezoneOffset());
      }
    } catch (e) {}

    fr.remove();

    const uniqLies = Array.from(new Set(lies));
    R.lies = uniqLies;
    R.iframeDiffs = frameDiffs;

    setProbe("iframe", frameDiffs.length ? `沙箱读数不符：${frameDiffs.join(", ")}` : "空白 iframe 与主页面 8 项核心读数一致", {
      tone: frameDiffs.length ? "bad" : "ok"
    });
    setProbe("lies", uniqLies.length ? `抓获 ${uniqLies.length} 处被钩子重写的接口：${uniqLies.slice(0, 4).join(" · ")}${uniqLies.length > 4 ? "…" : ""}` : `检验 ${testedCount} 项核心原生原型与属性，未发现篡改`, {
      tone: uniqLies.length ? "bad" : "ok",
      why: uniqLies.length ? `全部异常接口:\n${uniqLies.join("\n")}` : ""
    });
  }

  // 13. Fonts (52 Representative Fonts + Windows Exclusive System Fonts)
  const PROBE_FONTS = [
    // Windows & Office
    "Segoe UI", "Calibri", "Cambria", "Consolas", "Microsoft YaHei", "SimSun", "FangSong", "KaiTi", "DengXian", "Microsoft JhengHei",
    // macOS & Apple
    "PingFang SC", "PingFang TC", "Hiragino Sans", "Helvetica Neue", "Menlo", "SF Pro Display", "Avenir", "Songti SC", "DIN Alternate", "Futura", "Apple SD Gothic Neo",
    // CJK JP / KR / Intl
    "Yu Gothic", "Meiryo", "MS Gothic", "BIZ UDGothic", "Malgun Gothic", "Batang", "Leelawadee UI", "Nirmala UI",
    // Linux
    "Ubuntu", "DejaVu Sans", "Liberation Sans", "Noto Sans CJK SC", "WenQuanYi Micro Hei", "Cantarell", "Roboto",
    // Developer & Coding
    "JetBrains Mono", "Fira Code", "Cascadia Code", "Source Code Pro", "Hack", "Inconsolata", "Monaco",
    // Creative & Design
    "Aptos", "Myriad Pro", "Minion Pro", "Source Han Sans SC", "Adobe Clean", "Proxima Nova",
    // Classic Web
    "Arial", "Times New Roman", "Courier New"
  ];
  const WIN_VER_FONTS = ["Segoe Fluent Icons", "Segoe MDL2 Assets", "Segoe UI Emoji", "Segoe UI"];

  async function probeFonts() {
    const ctx = document.createElement("canvas").getContext("2d");
    if (!ctx) {
      R.fonts = [];
      setNA("fonts");
      setNA("fontfp");
      return;
    }
    const sample = "mmmmmmmmmlli你是谁あア한1WO@#";
    const bases = ["monospace", "sans-serif", "serif"];
    const measure = f => { ctx.font = `72px ${f}`; return ctx.measureText(sample).width; };
    const baseW = bases.map(measure);
    const hasFont = name => bases.some((b, i) => measure(`"${name}", ${b}`) !== baseW[i]);

    R.fonts = PROBE_FONTS.filter(hasFont);
    R.sysWinFonts = WIN_VER_FONTS.filter(hasFont);

    const fHash = shortHash(await sha256(R.fonts.slice().sort().join("|")));
    R.fontHash = fHash;

    // Persona hints from fonts
    const roles = [];
    const devHit = R.fonts.find(f => ["JetBrains Mono", "Fira Code", "Cascadia Code", "Source Code Pro", "Hack", "Inconsolata"].includes(f));
    const desHit = R.fonts.find(f => ["Myriad Pro", "Minion Pro", "Adobe Clean", "DIN Alternate", "Proxima Nova", "Source Han Sans SC"].includes(f));
    const offHit = R.fonts.find(f => ["Aptos", "Calibri", "Cambria"].includes(f));
    if (devHit) roles.push(["dev", `开发者 (${devHit})`]);
    if (desHit) roles.push(["design", `设计/创意 (${desHit})`]);
    if (offHit) roles.push(["office", `Office 办公 (${offHit})`]);
    R.fontRoles = roles;

    setProbe("fonts", `检出 ${R.fonts.length}/${PROBE_FONTS.length} 款：${R.fonts.slice(0, 6).join(", ")}${R.fonts.length > 6 ? "…" : ""}`, {
      why: `全部检出字体:\n${R.fonts.join(", ")}`
    });
    setProbe("fontfp", `${fHash}${roles.length ? " · 软件画像: " + roles.map(r => r[1]).join(" / ") : ""}`);
  }

  // 14. Canvas 2D Fingerprint, Dual-Draw Randomization & 16×16 Checkerboard Pixel Noise Trap
  async function probeCanvas() {
    const drawScene = () => {
      const c = document.createElement("canvas");
      c.width = 260; c.height = 64;
      const x = c.getContext("2d");
      if (!x) return "";
      const g = x.createLinearGradient(0, 0, 260, 64);
      g.addColorStop(0, "#2563eb"); g.addColorStop(0.5, "#0d9488"); g.addColorStop(1, "#f59e0b");
      x.fillStyle = g; x.fillRect(0, 0, 260, 18);
      x.font = "15px 'Arial', sans-serif";
      x.fillStyle = "rgba(15, 23, 42, 0.88)";
      x.fillText("WhoProbe L3-L7 指纹透视 🌐 0123456789", 6, 40);
      x.strokeStyle = "rgba(220, 38, 38, 0.75)";
      x.beginPath(); x.arc(225, 38, 16, 0, Math.PI * 1.65); x.stroke();
      return c.toDataURL();
    };

    try {
      const d1 = drawScene(), d2 = drawScene();
      if (!d1) {
        setNA("canvas"); setNA("rand"); setNA("pxnoise");
        return;
      }
      const h1 = shortHash(await sha256(d1));
      R.canvasHash = h1;
      R.canvasRand = d1 !== d2;
      setProbe("canvas", h1);
      setProbe("rand", R.canvasRand ? "每次调用随机变化（防指纹动态加噪已介入）" : "稳定一致（两次重绘输出完全相同）", {
        tone: R.canvasRand ? "warn" : "neutral"
      });
    } catch (e) {
      setNA("canvas"); setNA("rand");
    }

    // 32x32 Two-color + 16x16 Single-pixel Checkerboard Noise Trap
    try {
      const c = document.createElement("canvas");
      c.width = 32; c.height = 16;
      const x = c.getContext("2d", { willReadFrequently: true });
      // Left 16x16: two solid blocks (#6496c8 and #c86450)
      x.fillStyle = "rgb(100, 150, 200)"; x.fillRect(0, 0, 8, 16);
      x.fillStyle = "rgb(200, 100, 80)"; x.fillRect(8, 0, 8, 16);
      // Right 16x16: 1px checkerboard (every pixel touches 4 neighbors of another color -> triggers smart edge noisifiers!)
      for (let py = 0; py < 16; py++) {
        for (let px = 0; px < 16; px++) {
          x.fillStyle = (px + py) % 2 === 0 ? "rgb(40, 120, 210)" : "rgb(210, 140, 50)";
          x.fillRect(16 + px, py, 1, 1);
        }
      }
      const img = x.getImageData(0, 0, 32, 16).data;
      let tamperedPx = 0;
      for (let py = 0; py < 16; py++) {
        for (let px = 0; px < 32; px++) {
          const idx = (py * 32 + px) * 4;
          let exp;
          if (px < 8) exp = [100, 150, 200, 255];
          else if (px < 16) exp = [200, 100, 80, 255];
          else exp = (px - 16 + py) % 2 === 0 ? [40, 120, 210, 255] : [210, 140, 50, 255];
          if (img[idx] !== exp[0] || img[idx + 1] !== exp[1] || img[idx + 2] !== exp[2] || img[idx + 3] !== exp[3]) {
            tamperedPx++;
          }
        }
      }
      R.pxNoise = tamperedPx > 0;
      setProbe("pxnoise", tamperedPx > 0 ? `抓获隐蔽像素篡改！(${tamperedPx}/512 个已知校验像素被改写)` : "纯净原图回读（512 个棋盘格像素零篡改）", {
        tone: tamperedPx > 0 ? "warn" : "ok"
      });
    } catch (e) { setNA("pxnoise"); }
  }

  function probeShield() {
    const brName = R.br?.name || "";
    const lies = R.lies || [];
    const noisy = !!(R.pxNoise || R.auNoise || R.canvasRand);
    const isRfp = /Firefox/.test(navigator.userAgent) && R.tz === "UTC" && (!R.gpuRaw || /Mozilla|Generic/i.test(R.gpuRaw));
    const hasCanvasHook = lies.some(x => /Canvas|WebGL|AudioBuffer|Analyser|OfflineAudio/.test(x));
    const hasUaHook = lies.some(x => /userAgent|platform|appVersion/.test(x));
    const isApple = brName === "Safari" || /^(iOS|iPadOS)/.test(R.dev?.os || "");

    let label = "未开启防指纹护盾（真实硬件特征裸奔）";
    let kind = "none";
    if (navigator.brave) {
      kind = noisy ? "brave" : "brave_off";
      label = noisy ? "Brave 原生防指纹护盾 (Farbling 已生效)" : "Brave 浏览器 (当前站点防指纹护盾已关)";
    } else if (isRfp) {
      kind = "rfp";
      label = "Firefox resistFingerprinting (强隐私统一伪装)";
    } else if (/Firefox/.test(brName) && noisy) {
      kind = "fpp";
      label = "Firefox 增强型防指纹保护 (FPP 加噪)";
    } else if (isApple && noisy) {
      kind = "atfp";
      label = "Safari 高级防追踪与指纹保护";
    } else if (hasCanvasHook) {
      kind = "ext";
      label = "第三方防指纹扩展注入（已被原型检测识破）";
    } else if (hasUaHook) {
      kind = "ua_ext";
      label = "浅层改 UA 扩展（仅覆盖 JS 属性，已露馅）";
    } else if (noisy) {
      kind = "custom_noise";
      label = "指纹浏览器或内核级底层像素/音频加噪";
    }
    R.shieldKind = kind;
    R.shieldLabel = label;
    setProbe("shield", label, { tone: kind === "ext" || kind === "ua_ext" ? "bad" : kind === "none" ? "neutral" : "ok" });
  }

  // 15. Subpixel Geometry, Math Library, Engine Surface, Timer & Navigation Timing (8 items)
  async function probeSubpixelAndEngine() {
    // DOMRect rotated subpixel layout
    try {
      const d = document.createElement("div");
      d.style.cssText = "position:absolute;left:-9999px;top:0;font:16px serif;width:max-content";
      d.innerHTML = '<span style="display:inline-block;transform:rotate(7.3deg) skewX(3deg)">WhoProbe 你是谁 😃</span><span style="font:italic 13px monospace;letter-spacing:.37px">0.123 WWW</span>';
      document.body.appendChild(d);
      const pts = Array.from(d.querySelectorAll("span")).flatMap(s =>
        Array.from(s.getClientRects()).map(r => [r.x, r.y, r.width, r.height].map(v => v.toFixed(6)).join(","))
      );
      const rg = document.createRange();
      rg.selectNodeContents(d);
      const rb = rg.getBoundingClientRect();
      pts.push(`${rb.width.toFixed(6)},${rb.height.toFixed(6)}`);
      d.remove();
      setProbe("domrect", shortHash(await sha256(pts.join("|"))));
    } catch (e) { setNA("domrect"); }

    // SVG text bbox
    try {
      const ns = "http://www.w3.org/2000/svg";
      const svg = document.createElementNS(ns, "svg");
      const tx = document.createElementNS(ns, "text");
      svg.setAttribute("style", "position:absolute;left:-9999px;top:0");
      tx.setAttribute("x", "0"); tx.setAttribute("y", "20"); tx.setAttribute("font-size", "17");
      tx.textContent = "Cwm fjordbank glyphs vext quiz 你是谁 😃";
      svg.appendChild(tx);
      document.body.appendChild(svg);
      const b = tx.getBBox();
      const raw = [b.width, b.height, tx.getComputedTextLength(), tx.getSubStringLength(0, 10)].map(x => x.toFixed(6)).join(",");
      svg.remove();
      setProbe("svgrect", shortHash(await sha256(raw)));
    } catch (e) { setNA("svgrect"); }

    // Canvas TextMetrics bounding box
    try {
      const ctx = document.createElement("canvas").getContext("2d");
      const vals = ["16px serif", "16px sans-serif", "16px monospace", "italic 15px cursive"].map(f => {
        ctx.font = f;
        const m = ctx.measureText("WhoProbe? 你是谁 😃 1ms");
        return [m.width, m.actualBoundingBoxAscent, m.actualBoundingBoxDescent, m.actualBoundingBoxLeft, m.actualBoundingBoxRight].map(v => (+v || 0).toFixed(5)).join(",");
      });
      setProbe("textm", shortHash(await sha256(vals.join("|"))));
    } catch (e) { setNA("textm"); }

    // Math library precision fingerprint
    const mathVals = [
      Math.acos(0.123456789012345), Math.asin(0.123456789012345), Math.atan(2), Math.atanh(0.5),
      Math.cbrt(100), Math.cosh(1), Math.expm1(1), Math.log1p(10), Math.sinh(1), Math.tan(-1e300),
      Math.pow(Math.PI, -100), Math.sin(1e20)
    ].map(String).join("|");
    R.mathHash = shortHash(await sha256(mathVals));
    setProbe("mathfp", R.mathHash);

    // Engine global object property counts
    const wCnt = Object.getOwnPropertyNames(window).length;
    const hCnt = Object.getOwnPropertyNames(HTMLElement.prototype).length;
    const cCnt = getComputedStyle(document.documentElement).length;
    setProbe("keys", `window ${wCnt} · HTMLElement ${hCnt} · CSS属性 ${cCnt}`);

    // High-res timer step
    let minStep = Infinity, last = performance.now();
    for (let i = 0; i < 25000; i++) {
      const cur = performance.now();
      if (cur > last) { minStep = Math.min(minStep, cur - last); last = cur; }
    }
    setProbe("timer", minStep === Infinity ? "被冻结/粗化" : `最小步长 ${+minStep.toFixed(4)} ms${minStep >= 1 ? " (防指纹时钟降精度)" : " (微秒级高精度)"}`);

    // Callstack recursion depth
    let depth = 0;
    const rec = () => { depth++; rec(); };
    try { rec(); } catch (e) {}
    setProbe("callstack", `最大栈深 ${depth.toLocaleString("zh-CN")} 层`);

    // Navigation timing
    const nav = performance.getEntriesByType("navigation")[0];
    if (nav) {
      const tlsMs = nav.secureConnectionStart > 0 ? Math.round(nav.connectEnd - nav.secureConnectionStart) : 0;
      const ttfbMs = Math.round(nav.responseStart - nav.requestStart);
      setProbe("perf_nav", `协议 ${nav.nextHopProtocol || "h2"} · TLS耗时 ${tlsMs}ms · 首字节 ${ttfbMs}ms`);
    } else setNA("perf_nav");

    // 15b. WASM 128-bit SIMD & Hypervisor VM-Exit CPU Steal Jitter (cpubench)
    try {
      const simdWasm = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 8, 1, 6, 0, 65, 0, 253, 15, 11]);
      const simdOk = typeof WebAssembly === "object" && typeof WebAssembly.validate === "function" && WebAssembly.validate(simdWasm);
      const slices = [];
      let acc = 1.000001;
      for (let s = 0; s < 60; s++) {
        const t0 = performance.now();
        for (let k = 0; k < 18000; k++) {
          acc = (acc * 1.0000003 + 0.0000007) % 1024;
        }
        slices.push(Math.max(0.005, performance.now() - t0));
      }
      const sorted = slices.slice().sort((a, b) => a - b);
      const p50 = sorted[Math.floor(sorted.length * 0.5)];
      const p98 = sorted[Math.floor(sorted.length * 0.98)];
      const stealRatio = p50 > 0 ? +(p98 / p50).toFixed(2) : 1;
      R.cpuBench = { simdOk, p50Ms: +p50.toFixed(3), p98Ms: +p98.toFixed(3), stealRatio, sink: acc };
      setProbe("cpubench", `WASM SIMD ${simdOk ? "支持" : "不支持"} · 单片中位 ${p50.toFixed(2)}ms · 抢占抖动比 p98/p50=${stealRatio}x`, {
        tone: stealRatio >= 5.5 ? "warn" : "ok",
        why: `60 组紧致浮点时间片 p50=${p50.toFixed(3)}ms, p98=${p98.toFixed(3)}ms（超售云主机或虚拟机发生 Hypervisor VM-Exit 时尾延迟显著放大）`
      });
    } catch (e) { setNA("cpubench"); }

    // 15c. Native Form Control Subpixel Geometry (uigeom)
    try {
      const box = document.createElement("div");
      box.style.cssText = "position:absolute;left:-9999px;top:0;all:initial;font-family:sans-serif;font-size:16px";
      box.innerHTML = '<button id="_uib">Ag</button><select id="_uis"><option>Ag</option></select><input id="_uic" type="checkbox"><input id="_uir" type="range">';
      document.body.appendChild(box);
      const dims = ["_uib", "_uis", "_uic", "_uir"].map(id => {
        const r = box.querySelector("#" + id).getBoundingClientRect();
        return [+(r.width.toFixed(2)), +(r.height.toFixed(2))];
      });
      box.remove();
      const uiSig = dims.map(([w, h]) => `${w}×${h}`).join(" / ");
      const uiHash = shortHash(await sha256(uiSig));
      R.uiGeom = { dims, sig: uiSig, hash: uiHash, chkW: dims[2][0], btnH: dims[0][1] };
      setProbe("uigeom", `${uiHash} · 按钮 ${dims[0][0]}×${dims[0][1]} · 勾选框 ${dims[2][0]}×${dims[2][1]}`, {
        why: `原生控件几何 (button / select / checkbox / range): ${uiSig}`
      });
    } catch (e) { setNA("uigeom"); }

    // 15d. Cross-OS Font Rasterizer Channel Divergence & Gamma Signature (fontrast)
    try {
      const cv = document.createElement("canvas");
      cv.width = 160; cv.height = 44;
      const cx = cv.getContext("2d", { alpha: false, willReadFrequently: true });
      cx.fillStyle = "#ffffff";
      cx.fillRect(0, 0, 160, 44);
      cx.fillStyle = "#000000";
      cx.font = "32px system-ui, -apple-system, 'Segoe UI', sans-serif";
      cx.fillText("Qg@永W", 4, 34);
      const data = cx.getImageData(0, 0, 160, 44).data;
      let edgePx = 0, rgbDiffPx = 0, midGammaSum = 0;
      for (let i = 0; i < data.length; i += 4) {
        const r = data[i], g = data[i + 1], b = data[i + 2];
        if (r === 255 && g === 255 && b === 255) continue;
        if (r === 0 && g === 0 && b === 0) continue;
        edgePx++;
        if (Math.abs(r - b) >= 6 || Math.abs(r - g) >= 6) rgbDiffPx++;
        midGammaSum += (r + g + b) / 3;
      }
      const rgbRatio = edgePx > 0 ? +(rgbDiffPx / edgePx).toFixed(3) : 0;
      const avgMidLuma = edgePx > 0 ? +(midGammaSum / edgePx).toFixed(1) : 0;
      const rastEngine = rgbRatio >= 0.18
        ? "DirectWrite / FreeType LCD 彩边引擎"
        : avgMidLuma >= 142
        ? "Apple CoreText 灰阶平滑引擎"
        : "FreeType / Skia 标准灰阶引擎";
      R.fontRast = { rgbRatio, avgMidLuma, edgePx, engine: rastEngine };
      setProbe("fontrast", `${rastEngine} (彩边率 ${(rgbRatio * 100).toFixed(1)}% · 边缘均值亮度 ${avgMidLuma})`, {
        why: `半透明抗锯齿像素数: ${edgePx} · RGB 异色通道像素: ${rgbDiffPx}\n注：即使在 Linux/Windows 容器内拷贝安装苹果字体文件，其光栅化彩边率与 Gamma 曲线仍会暴露真实图形栈`
      });
    } catch (e) { setNA("fontrast"); }
  }

  // 16. Stateless ETag Cache Tracking, 4-Store Survival & Composite IDs (4 items + 3 manual buttons)
  async function probeEtag() {
    try {
      const res = await within(fetch("./api/who/etag", { cache: "no-cache", credentials: "same-origin" }), 4500, null);
      if (!res || (!res.ok && res.status !== 304)) return setNA("etag", "ETag 接口不可达");
      const j = await res.json().catch(() => null);
      if (!j?.etagId) return setNA("etag");
      const seen = !!(j.seenBefore ?? j.returning);
      R.etag = { id: j.etagId, seen };
      setProbe("etag", `${j.etagId.slice(0, 8)} · ${seen ? "老访客（浏览器缓存自动回传了上次的 ETag 追踪码！）" : "首次分配缓存标记（刷新或清 Cookie 后再来即会命中）"}`, {
        tone: seen ? "warn" : "neutral"
      });
    } catch (e) { setNA("etag"); }
  }

  async function probeTraces() {
    const readIdb = () => new Promise(resolve => {
      if (!window.indexedDB) return resolve(null);
      try {
        const req = indexedDB.open("whoprobe_store", 1);
        req.onupgradeneeded = () => { try { req.result.createObjectStore("kv"); } catch (e) {} };
        req.onerror = () => resolve(null);
        req.onsuccess = () => {
          const db = req.result;
          try {
            const tx = db.transaction("kv", "readonly");
            const g = tx.objectStore("kv").get("tag");
            g.onsuccess = () => { db.close(); resolve(g.result || null); };
            g.onerror = () => { db.close(); resolve(null); };
          } catch (e) { db.close(); resolve(null); }
        };
      } catch (e) { resolve(null); }
    });
    const writeIdb = val => new Promise(resolve => {
      if (!window.indexedDB) return resolve(false);
      try {
        const req = indexedDB.open("whoprobe_store", 1);
        req.onupgradeneeded = () => { try { req.result.createObjectStore("kv"); } catch (e) {} };
        req.onerror = () => resolve(false);
        req.onsuccess = () => {
          const db = req.result;
          try {
            const tx = db.transaction("kv", "readwrite");
            tx.objectStore("kv").put(val, "tag");
            tx.oncomplete = () => { db.close(); resolve(true); };
            tx.onerror = () => { db.close(); resolve(false); };
          } catch (e) { db.close(); resolve(false); }
        };
      } catch (e) { resolve(false); }
    });
    const readCache = async () => {
      if (!window.caches) return null;
      try {
        const c = await caches.open("whoprobe_cache");
        const r = await c.match("/__whoprobe_tag");
        return r ? await r.text() : null;
      } catch (e) { return null; }
    };
    const writeCache = async val => {
      if (!window.caches) return false;
      try {
        const c = await caches.open("whoprobe_cache");
        await c.put("/__whoprobe_tag", new Response(val));
        return true;
      } catch (e) { return false; }
    };

    const lsVal = store.get(SK.traceTag);
    const idbVal = await within(readIdb(), 1200, null);
    const caVal = await within(readCache(), 1200, null);
    const wnVal = /^wp:([0-9a-f]{8})$/.exec(window.name || "")?.[1] || null;

    const existing = lsVal || idbVal || caVal || wnVal;
    const survived = [
      lsVal && "LocalStorage",
      idbVal && "IndexedDB",
      caVal && "CacheStorage",
      wnVal && "window.name"
    ].filter(Boolean);

    const tag = existing || Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, "0")).join("");
    store.set(SK.traceTag, tag);
    await Promise.all([within(writeIdb(tag), 1000, false), within(writeCache(tag), 1000, false)]);
    try { if (!window.name || /^wp:/.test(window.name)) window.name = `wp:${tag}`; } catch (e) {}

    R.traceTag = tag;
    R.traceSurvived = survived;
    const btnForget = $("#btnForget");
    if (btnForget) btnForget.hidden = false;

    if (survived.length) {
      const revived = !lsVal && survived.length > 0;
      setProbe("traces", `认出旧标记 ${tag} · 存活于 ${survived.join(" + ")}${revived ? "（LocalStorage 已清但被其他存储复活！）" : ""}`, {
        tone: revived ? "bad" : "warn"
      });
    } else {
      setProbe("traces", `全新会话（已向 4 大存储写入测试标记 ${tag}，重开或清理后可验留存）`);
    }
  }

  function drawFpSigil(hex) {
    const svg = $("#fpSigil");
    if (!svg || !hex || hex.length < 32) return;
    const bytes = [];
    for (let i = 0; i < 16; i++) bytes.push(parseInt(hex.slice(i * 2, i * 2 + 2), 16) || 0);
    const cx = 32, cy = 32;
    let paths = `<circle cx="32" cy="32" r="28" stroke-opacity="0.18"/>`;
    const pts = [];
    for (let i = 0; i < 8; i++) {
      const ang = (i * Math.PI) / 4 - Math.PI / 2;
      const rad = 10 + (bytes[i] / 255) * 18;
      const x = (cx + Math.cos(ang) * rad).toFixed(1);
      const y = (cy + Math.sin(ang) * rad).toFixed(1);
      pts.push(`${x},${y}`);
      paths += `<line x1="32" y1="32" x2="${x}" y2="${y}" stroke-opacity="0.25"/>`;
    }
    paths += `<polygon points="${pts.join(" ")}" stroke-linejoin="round" fill="currentColor" fill-opacity="0.08"/>`;
    const rInner = 4 + (bytes[8] % 5);
    paths += `<circle cx="32" cy="32" r="${rInner}"/>`;
    svg.innerHTML = paths;
  }

  async function probeCompositeIds() {
    const osFam = (R.dev?.os || "").split(" ")[0];
    const hwParts = [
      osFam,
      R.physScreen,
      screen.colorDepth,
      navigator.hardwareConcurrency || "",
      R.gpuClean || "",
      R.gpuDiscrete || "",
      R.tz || "",
      (R.fonts || []).slice().sort().join(",")
    ];
    const hwFull = await sha256(hwParts.join("|"));
    R.hwId = shortHash(hwFull);
    setProbe("hwid", `${R.hwId}（由屏幕/核数/显卡/时区/字库决定，换浏览器仍一致）`);

    const fpParts = [
      ...hwParts,
      R.canvasRand ? "canvas_rand" : (R.canvasHash || ""),
      R.webglHash || "",
      R.auNoise ? "audio_rand" : (R.audioHash || ""),
      R.mathHash || "",
      (R.langs || []).join(","),
      R.engine || ""
    ];
    const fpFull = await sha256(fpParts.join("|"));
    R.fpId = shortHash(fpFull);
    R.fpFull = fpFull;
    setProbe("fpid", `${R.fpId}${R.canvasRand || R.auNoise ? "（已受动态防指纹加噪干扰）" : "（稳定跨站唯一标识）"}`);

    // Update KPI 4
    $("#kpiFpId").textContent = R.fpId;
    $("#kpiHwId").textContent = `跨浏览器硬件码: ${R.hwId}`;
    drawFpSigil(fpFull);

    const visitEl = $("#kpiVisitState");
    if (visitEl) {
      if (R.etag?.seen && (!R.traceSurvived || !R.traceSurvived.includes("LocalStorage"))) {
        visitEl.textContent = "清除了本地存储，但被 HTTP ETag 缓存认出回访";
        visitEl.className = "text-amber-600 dark:text-amber-400 font-medium truncate";
      } else if (R.traceSurvived?.length) {
        visitEl.textContent = `回访识别：${R.traceSurvived.length}/4 个浏览器存储命中`;
      } else {
        visitEl.textContent = "首次访问或无痕隔离状态良好";
      }
    }
  }

  function haversineKm(lat1, lon1, lat2, lon2) {
    const rad = d => (d * Math.PI) / 180;
    const h = Math.sin(rad(lat2 - lat1) / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(rad(lon2 - lon1) / 2) ** 2;
    return 12742 * Math.asin(Math.sqrt(h));
  }

  function initInteractiveProbes() {
    // 1. 7-Tracker Blocking Live Test
    const TRACKER_URLS = [
      ["Google Analytics", "https://www.google-analytics.com/analytics.js"],
      ["DoubleClick Ads", "https://securepubads.g.doubleclick.net/tag/js/gpt.js"],
      ["Meta Pixel", "https://connect.facebook.net/en_US/fbevents.js"],
      ["Bing Ads", "https://bat.bing.com/bat.js"],
      ["TikTok Pixel", "https://analytics.tiktok.com/i18n/pixel/events.js"],
      ["百度统计", "https://hm.baidu.com/hm.js"],
      ["Hotjar", "https://static.hotjar.com/c/hotjar-0.js?sv=6"]
    ];
    setProbe("trackers", `<button type="button" id="btnRunTrackers" class="py-0.5 px-2 rounded bg-blue-50 text-blue-700 hover:bg-blue-100 font-sans font-medium text-[11px] dark:bg-blue-500/15 dark:text-blue-400">点击实测 7 大追踪器拦截</button>`, {
      html: true, rawText: "未触发手动实测"
    });
    const btnTr = $("#btnRunTrackers");
    if (btnTr) {
      btnTr.onclick = async ev => {
        ev.stopPropagation();
        btnTr.disabled = true;
        btnTr.textContent = "正在并发探测 7 路追踪器…";
        const res = await Promise.all(TRACKER_URLS.map(async ([name, url]) => {
          const t0 = performance.now();
          try {
            const st = await within(fetch(url, { mode: "no-cors", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" }).then(() => "ok"), 5000, "net");
            return [name, st];
          } catch (e) {
            return [name, performance.now() - t0 < 60 ? "blocked" : "net"];
          }
        }));
        const blocked = res.filter(([, s]) => s === "blocked").map(([n]) => n);
        const passed = res.filter(([, s]) => s === "ok").map(([n]) => n);
        setProbe("trackers", `成功拦截 ${blocked.length}/${TRACKER_URLS.length} 个${passed.length ? ` · 放行: ${passed.join("、")}` : " (全数阻断)"}`, {
          tone: blocked.length >= 5 ? "ok" : blocked.length > 0 ? "neutral" : "warn",
          why: res.map(([n, s]) => `${n}: ${s === "blocked" ? "本地规则秒拒" : s === "ok" ? "放行加载" : "网络超时"}`).join("\n")
        });
      };
    }

    // 2. Geolocation Distance vs IP Geo
    if (!navigator.geolocation) {
      setNA("geoloc", "浏览器不支持定位 API");
    } else {
      setProbe("geoloc", `<button type="button" id="btnRunGeo" class="py-0.5 px-2 rounded bg-blue-50 text-blue-700 hover:bg-blue-100 font-sans font-medium text-[11px] dark:bg-blue-500/15 dark:text-blue-400">点击授权定位对比出口距离</button>`, {
        html: true, rawText: "未授权手动实测"
      });
      const btnGeo = $("#btnRunGeo");
      if (btnGeo) {
        btnGeo.onclick = ev => {
          ev.stopPropagation();
          btnGeo.disabled = true;
          btnGeo.textContent = "等待系统定位授权…";
          navigator.geolocation.getCurrentPosition(pos => {
            const { latitude: la, longitude: lo, accuracy: acc } = pos.coords;
            const dist = R.ipLat != null ? Math.round(haversineKm(R.ipLat, R.ipLon, la, lo)) : null;
            setProbe("geoloc", `精度 ±${Math.round(acc)}m${dist != null ? ` · 距当前出口 IP 物理相隔 ${dist.toLocaleString("zh-CN")} km` : ""}`, {
              tone: dist != null && dist > 300 ? "bad" : "ok"
            });
          }, err => {
            setProbe("geoloc", err.code === 1 ? "已拒绝定位权限（隐私保护良好）" : "系统定位获取失败", { na: true });
          }, { enableHighAccuracy: true, timeout: 12000, maximumAge: 0 });
        };
      }
    }

    // 3. Mobile Motion Sensors Calibration Noise
    if (!window.DeviceMotionEvent || !mq("(pointer: coarse)")) {
      setProbe("sensors", "桌面端无陀螺仪硬件（仅触屏移动设备适用）", { na: true });
    } else {
      setProbe("sensors", `<button type="button" id="btnRunSensor" class="py-0.5 px-2 rounded bg-blue-50 text-blue-700 hover:bg-blue-100 font-sans font-medium text-[11px] dark:bg-blue-500/15 dark:text-blue-400">点击采集 1.5s 传感器硬件指纹</button>`, {
        html: true, rawText: "移动端待手动实测"
      });
      const btnSn = $("#btnRunSensor");
      if (btnSn) {
        btnSn.onclick = async ev => {
          ev.stopPropagation();
          btnSn.disabled = true;
          if (typeof DeviceMotionEvent.requestPermission === "function") {
            const perm = await DeviceMotionEvent.requestPermission().catch(() => "denied");
            if (perm !== "granted") return setProbe("sensors", "已拒绝动作与方向权限", { na: true });
          }
          btnSn.textContent = "请保持手机静止 1.5 秒…";
          const samples = [];
          const handler = e => {
            const g = e.accelerationIncludingGravity || {}, r = e.rotationRate || {};
            samples.push([g.x || 0, g.y || 0, g.z || 0, r.alpha || 0, r.beta || 0, r.gamma || 0]);
          };
          window.addEventListener("devicemotion", handler);
          await new Promise(r => setTimeout(r, 1500));
          window.removeEventListener("devicemotion", handler);
          if (samples.length < 5) return setProbe("sensors", "未收到传感器硬件读数", { na: true });
          const hz = Math.round(samples.length / 1.5);
          const mean = i => samples.reduce((a, b) => a + b[i], 0) / samples.length;
          const sig = await sha256([0, 1, 2, 3, 4, 5].map(i => mean(i).toFixed(3)).join(","));
          setProbe("sensors", `采样率 ${hz} Hz · 零偏指纹 ${shortHash(sig)}`);
        };
      }
    }
  }


  /* ---------- 24 Cross-Layer Disguise, Deep Stack, Reputation & Protocol Checks Evaluator ---------- */
  const CHECK_WEIGHTS = {
    bot: 9, webrtc: 9, reality: 9, conn: 8, split: 8, reputation: 8,
    dns: 7, tz: 7, tamper: 7, fpb: 7, synspoof: 6, ua: 6,
    dc: 6, rtt: 5, lease: 5, subpixel: 5, hwvirt: 4, lang: 4, syslang: 3, fp: 3
  };

  function getFixSteps(id) {
    const os = R.dev?.os || "macOS";
    const br = R.br?.name || "Chrome";
    const ipTz = R.ipTz || "America/Los_Angeles";
    const ipCountry = countryName(R.ipCC || "US");

    const osTzStep = os === "macOS"
      ? `macOS：打开「系统设置 → 通用 → 日期与时间」，关闭「使用当前位置自动设置时区」，手动改为 ${ipTz}。`
      : os === "Windows"
      ? `Windows：打开「设置 → 时间和语言 → 日期和时间」，关闭「自动设置时区」，手动选择与 ${ipCountry} 对应的时区。`
      : `系统设置 → 日期与时间：关闭自动时区，手动切换至 ${ipTz}（切勿用浏览器改时区插件，会被原型检测直接抓包）。`;

    const GUIDE = {
      tz: [
        osTzStep,
        "修改系统时区后无需清缓存，直接点击右侧「重测」按钮即可实时验证是否对齐。",
        "避免使用浏览器扩展篡改 Date / Intl 时区——这类插件只改主页面 JS，不仅在 Worker 线程露馅，还会触发「环境篡改」告警。"
      ],
      lang: [
        br === "Safari"
          ? `macOS Safari：在「系统设置 → 通用 → 语言与地区」中为 Safari 单独将目标地区语言（如英语 en-US）拖到首位。`
          : `${br}：打开浏览器「设置 → 语言 (chrome://settings/languages)」，将 ${ipCountry} 常用语言移至第 1 位，并移除排在前面的中文项。`,
        "浏览器重启或刷新后，HTTP Accept-Language 请求头与 navigator.languages 会同步更新，不会留下篡改痕迹。"
      ],
      syslang: [
        "Windows 系统安装的区域语言包会暴露专属字库（如微软雅黑/SimSun）与离线朗读语音包（speechSynthesis）。",
        "高风控场景建议使用英文原版系统镜像或 macOS（全地区统一预装多国字体，不因语言包差异暴露国籍）。"
      ],
      dns: [
        "在 Clash / Surge / Sing-box / v2rayN 中开启「防 DNS 泄漏」：启用 Fake-IP 模式或强制远程代理解析 (Remote DNS)，避免本地 ISP 递归服务器发送 ECS 客户端子网。",
        `在 ${br}「设置 → 隐私和安全 → 安全」中开启「使用安全 DNS (DoH)」，选择与落地节点同国的 DoH 或让代理出口本网 ISP 负责递归解析。`
      ],
      split: [
        "当前开启了「绕过中国大陆 (Rule 规则分流)」，任何网页只需悄悄加载一个国内接口或测速图片，就能立刻拍到你的国内宽带真实省市与 IP！",
        "访问风控严格的海外平台（OpenAI / Claude / TikTok / Stripe / 跨境电商）时，请将代理客户端切换为「全局模式 (Global)」或「TUN 全局接管」。"
      ],
      conn: [
        "原理：服务端网卡直接抓到了建立连接的首个 TCP SYN 包。如果浏览器自报 macOS/Windows，而发包内核却是 Linux（TTL=64 配合 Linux 窗口/选项），说明代理节点服务器在替你发起 TCP 连接——哪怕开全局/TUN 也会被抓，因为远端落地机仍是 Linux！",
        "低成本规避：在远端代理机器上用 eBPF / NFQUEUE 工具按目标系统重写对外发包的 TTL、Window 与 TCP Options，但须保持整条连接状态一致（否则会被下一项「内核时钟防改包」识破）。",
        "终极根治：在代理链路最末端挂载真实同构系统住宅节点（如真 Mac mini / Windows 软路由出口，或原生住宅 SOCKS5 落地），或强制走 HTTP/3 (QUIC over UDP) 隐藏内核 TCP SYN 选项。"
      ],
      synspoof: [
        "服务端 AF_PACKET 同时比对了首包 SYN 与后续 TLS ClientHello 数据包的 IPv4 DF 分片位、IPID 递增规律及 TCP Timestamp (TSval) 内核节拍频率 (Hz)。",
        "若提示「无状态 SYN 改包」：说明代理机使用了 osfuscate 等仅篡改首个 SYN 包的工具，但后续数据包恢复了 Linux 原始内核时钟，被跨包连续性校验一眼拆穿。",
        "若提示「微脉冲多路复用粘包」：说明代理启用了 Mux / smux / yamux 或高抖动隧道合并转发；高敏感业务建议关闭代理客户端的 Mux 多路复用选项。"
      ],
      reality: [
        "服务端主动反向连接你当前出口 IP 的 :443 端口进行 TLS 证书归属验真：真实家庭宽带光猫在公网侧通常关闭 :443，绝不会挂载大厂官网证书。",
        "若检出「非官方 ASN 却返回 Microsoft / Apple / Yahoo / Amazon 等大厂证书」，这是 VLESS-Reality 借用他人域名证书的铁证——严苛风控一旦反向回探，100% 实锤代理节点！",
        "修复建议：将自建 Reality / TLS 节点监听端口迁离标准 :443，或在代理服务端配置 Outbound 链式转发至不开任何公网端口的纯净家宽落地 IP。"
      ],
      rtt: [
        "原理（三维物理测距）：① 服务端测量 TCP 握手耗时（代理节点→本站物理距离）；② 浏览器测量 HTTP 往返耗时（你的电脑→代理节点→本站）；③ WebRTC 测量 STUN UDP 候选耗时。三者差值直接框定「你到代理节点」多绕的物理路程，无法靠改浏览器插件伪造。",
        "有效解法：① 缩短第一跳物理距离——亚洲用户优先选用日本/新加坡/香港 IEPL/IPLC 专线（电脑→节点仅 +8~20ms，落入正常 Wi-Fi 抖动阈值内）；② 若必须用欧美住宅 IP，直接在同城云桌面（如美西 Mac/Win 远程主机）内打开浏览器，使浏览器与出口物理同地，实现 0ms 中转差！"
      ],
      webrtc: [
        `在代理客户端中开启「TUN 虚拟网卡模式（接管全局 UDP）」，使 STUN UDP 探测包与 TCP 走完全相同的代理出口。`,
        `或在 ${br} 安装官方 WebRTC Network Limiter 设置为「Disable non-proxied UDP」（走浏览器原生策略接口，不重写 JS 原型，零篡改痕迹）。`
      ],
      dc: [
        "融合了 8 家欺诈情报源（ipapi.is / IPQuery / IPLocate / IPinfo 等）对数赔率加权投票：当前出口被高置信度判定为云服务器/数据中心（Hosting/IDC）。",
        "注册或登录高风控账号时，建议在代理软件末端链式挂载（Dialer-Proxy / Relay）真实本土家庭宽带 ISP 静态住宅 IP。"
      ],
      lease: [
        "交叉审计了 RIR RDAP 注册国、PeeringDB 互联流量方向（Heavy Outbound 内容机房 vs Inbound 家宽）以及 IPXO / InterLIR 等商业 IP 租赁平台特征。",
        "许多市售「双 ISP 伪家宽 VPS」只是向经纪商租用老旧段广播到机房 ASN 上，风控结合 PeeringDB 流量比与子分配日期即可识破。",
        "高风控金融/社媒场景建议选择「RIR 注册国 = 路由国」且直接归属本土电信运营商（如 Comcast / AT&T / NTT / BT）的原生 IP。"
      ],
      reputation: [
        "并发检索了 12 家实时 DoH DNSBL 黑名单（Spamhaus ZEN、Barracuda、DroneBL 等）、15 份攻击/僵尸/代理 CIDR 库及同 /24 C 段脏邻居数量。",
        "即便单 IP 未直接上榜，若同 /24 C 段存在大量黑名单「脏邻居」，Cloudflare Turnstile 与支付网关仍会按网段连坐降权。",
        "修复建议：更换同 /24 零脏邻居、纯净度 ≥ 82 (S/A 级) 的干净网段；购买前可在页面顶部输入框粘贴候选 IP 提前验毒。"
      ],
      subpixel: [
        "即使在 Windows/Linux 容器或指纹浏览器中拷贝安装苹果字体并篡改 UA，底层的字体光栅化引擎（Apple CoreText 灰阶平滑 vs DirectWrite/FreeType RGB 彩边）、原生控件尺寸与滚动条宽度仍会暴露真实宿主系统。",
        "修复铁律：坚持「同构宿主机」原则——Windows 电脑只配 Windows 环境，Mac 电脑只配 macOS 环境，切勿跨系统硬改 UA。"
      ],
      hwvirt: [
        "通过 WebCodecs 视频硬解芯片探针、WebGL 渲染器与 60 组紧致浮点时间片尾延迟比（p98/p50）识别云主机 Hypervisor CPU 抢占（VM-Exit Steal）与无显卡容器。",
        "建议在具备真实物理 GPU 的本地电脑运行浏览器，仅将网络层通过链式代理转发，避免在廉价无 GPU 超售云桌面上操作核心账号。"
      ],
      tamper: [
        "检测到当前页面原生 JS 原型、Canvas/Audio 像素回读或 HTTP 请求头与 JS 读数不一致（通常由防关联插件、改 UA 扩展或注入式脚本引起）。",
        "建议打开无扩展的干净浏览器 Profile 测试；切勿在普通浏览器安装「Canvas Defender / User-Agent Switcher」等浅层插件（越装越容易被直接判定为黑产环境）。"
      ],
      fpb: [
        "指纹浏览器三大常见死穴：① 只改主线程忘了改 Web Worker；② 虚报新版 Chrome 但底层 Chromium 内核缺失新版 JS/CSS 特性；③ Windows 机器伪装成 Mac 但显卡渲染器仍暴露 Direct3D。",
        "修复建议：升级指纹浏览器到最新内核版本，并保持「真实宿主机系统 = Profile 伪装系统」。"
      ],
      ua: [
        "请关闭任何改 User-Agent 的插件或开发者工具设备模拟模式，保持 HTTP 请求头、Sec-CH-UA-Platform 与显卡驱动平台三者自然一致。"
      ],
      bot: [
        "当前浏览器暴露了 navigator.webdriver 或自动化调试协议标记（Selenium / Playwright / Puppeteer）。",
        "正常使用请直接双击打开原生浏览器；自动化测试需配合底层 C++ 级补丁或真实无注入隔离环境。"
      ],
      fp: [
        "常规 Chrome / Edge 允许网站通过 Canvas、WebGL、音频与 HTTP ETag 缓存生成跨站稳定指纹，清 Cookie 也无法摆脱。",
        "若追求强隐私防追踪（非账号养号场景），可使用 Brave 浏览器（内置动态 Farbling 随机加噪）或 Safari 无痕浏览。"
      ],
      pq: [
        "现代 Chrome 124+ / Edge / Firefox 已默认支持 X25519MLKEM768 后量子混合密钥交换；若显示未启用，通常是中间代理节点或旧版 TLS 库降级了握手。"
      ],
      ech: [
        "启用安全 DNS (DoH) 后，现代浏览器在访问配置了 HTTPS DNS 记录的站点时会自动加密 SNI 域名。"
      ],
      h3: [
        "许多代理协议（如仅转发 TCP 的隧道）会丢弃 UDP 443 流量，导致浏览器自动回退到 HTTP/2；开启 Sing-box / Mihomo 的 QUIC/UDP 转发即可恢复 HTTP/3。"
      ],
      warp: [
        "仅作链路属性提示：Cloudflare WARP 出口对普通浏览友好，但共享出口 IP 在部分严格站点可能触发人机验证。"
      ]
    };
    return GUIDE[id] || ["保持真实原生系统与纯净网络出口地区自然对齐即可。"];
  }

  function evaluateAllChecks() {
    const out = {};
    const ipCC = R.ipCC || "";
    const ipCountry = countryName(ipCC);

    // 1. tz: Timezone vs Exit IP
    if (!R.tz || !ipCC) {
      out.tz = { level: "info", summary: "等待出口 IP 与系统时区读数…" };
    } else {
      const userTzCC = tzCC(R.tz);
      const sameOff = R.tzOff != null && R.ipTzOff != null && R.tzOff === R.ipTzOff;
      if (userTzCC === ipCC || R.tz === R.ipTz) {
        out.tz = { level: "ok", summary: `系统时区 ${R.tz} (UTC${fmtUtcOffset(R.tzOff)}) 与 ${ipCountry} 出口一致` };
      } else if (!sameOff && R.ipTzOff != null) {
        out.tz = { level: "bad", summary: `时区严重穿帮：出口在 ${ipCountry} (${R.ipTz || ""} UTC${fmtUtcOffset(R.ipTzOff)})，系统时钟却是 ${R.tz} (UTC${fmtUtcOffset(R.tzOff)})` };
      } else {
        out.tz = { level: "warn", summary: `UTC 偏移相近，但系统时区 ID (${R.tz}) 指向 ${countryName(userTzCC)}，而非出口地 ${ipCountry}` };
      }
    }

    // 2. lang: Browser Language vs Exit IP
    const firstLang = (R.langs || [])[0] || "";
    if (!firstLang || !ipCC) {
      out.lang = { level: "info", summary: "等待语言与出口读数…" };
    } else {
      const spoken = spokenIn(firstLang);
      const lcc = langCC(firstLang);
      const isEn = /^en\b/i.test(firstLang);
      if (spoken.includes(ipCC) || lcc === ipCC) {
        out.lang = { level: "ok", summary: `首选语言 ${firstLang} (${languageName(firstLang)}) 符合 ${ipCountry} 当地习惯` };
      } else if (isEn) {
        out.lang = { level: "ok", summary: `首选语言为国际通用英语 (${firstLang})，在 ${ipCountry} 出口下属常见配置` };
      } else {
        out.lang = { level: "warn", summary: `首选语言为 ${firstLang} (${languageName(firstLang)})，但网络出口在 ${ipCountry}` };
      }
    }

    // 3. syslang: Underlying OS Fonts / Voices / Keyboard vs Exit IP
    const sys = inferSystemLangs({ os: R.dev?.os, sysFonts: R.fonts || [], voices: R.voices || [], kbd: R.kbd });
    if (!sys || !ipCC) {
      out.syslang = { level: "ok", summary: `${R.dev?.os || "当前系统"} 未暴露与出口矛盾的独有区域字库或键位` };
    } else if (!sys.cc.length || sys.cc.includes(ipCC)) {
      out.syslang = { level: "ok", summary: `系统底层字库、离线语音包与 ${R.kbd || "标准"} 键位未见跨区异常` };
    } else {
      const leakedCountries = sys.cc.map(countryName).join(" / ");
      const srcNames = sys.from.map(k => ({ fonts: "系统字库", voices: "离线语音包", kbd: "物理键盘布局" })[k] || k).join("、");
      out.syslang = { level: "warn", summary: `${srcNames}暴露系统装有 ${leakedCountries} 环境，与 ${ipCountry} 出口不一致` };
    }

    // 4. dns: Recursive DNS Resolver & EDNS Client Subnet vs Exit IP
    const ecsMismatch = R.ecsIp && R.ip && netPrefix(R.ecsIp) && netPrefix(R.ip) && netPrefix(R.ecsIp) !== netPrefix(R.ip);
    if (!R.dnsCC) {
      out.dns = { level: "info", summary: "DNS 递归探针未返回结果或被当前网络策略阻断" };
    } else if (R.dnsCC === "CN" && ipCC !== "CN") {
      out.dns = { level: "bad", summary: `致命 DNS 泄漏：网页出口在 ${ipCountry}，但替你解析域名的 DNS 仍在中国大陆 (${R.dnsIp})！` };
    } else if (ipCC && R.dnsCC !== ipCC) {
      out.dns = { level: "warn", summary: `跨国 DNS 偏移：出口在 ${ipCountry}，但递归 DNS 服务器位于 ${countryName(R.dnsCC)} (${R.dnsOrg})` };
    } else if (ecsMismatch) {
      out.dns = { level: "warn", summary: `DNS 同国，但上游递归暴露了异网段 ECS 客户端子网 (${R.ecsIp})` };
    } else {
      out.dns = { level: "ok", summary: `DNS 解析服务器位于 ${countryName(R.dnsCC)} (${R.dnsOrg})，与出口一致且无 ECS 子网泄露` };
    }

    // 5. split: Multi-target Split Tunneling
    const ex = R.exits || {};
    const cnIp = ex.ex_cn;
    const validExits = Object.entries(ex).filter(([, v]) => v && v.ip);
    const prefixes = new Set(validExits.map(([, v]) => netPrefix(v.ip)).filter(Boolean));
    const countries = new Set(validExits.map(([, v]) => v.cc).filter(Boolean));

    if (!R.exitsDone) {
      out.split = { level: "info", summary: "正在并发比对国内外与 AI 平台分流出口…" };
    } else if (cnIp && cnIp.cc === "CN" && ipCC && ipCC !== "CN") {
      out.split = { level: "bad", summary: `规则分流直接露底：本站走 ${ipCountry}，但大陆测速探针直连暴露真实国内宽带 (${cnIp.ip} · ${cnIp.label})！` };
    } else if (countries.size > 1 || prefixes.size > 1) {
      const detail = validExits.map(([k, v]) => `${({ ex_self: "本站", ex_cn: "国内", ex_intl: "国际", ex_gpt: "ChatGPT", ex_claude: "Claude", ex_cf: "CF" })[k] || k}:${v.cc || "?"}`).join(" / ");
      out.split = { level: "warn", summary: `检测到多路代理分流：浏览器并发请求落在了 ${prefixes.size} 个不同网段 (${detail})` };
    } else {
      out.split = { level: "ok", summary: `全局路由一致：所有测试目标均稳定走同一 ${ipCountry} 出口网段` };
    }

    // 6. conn: Passive TCP/TLS Stack vs Claimed OS
    const tcp = R.srv?.packet?.tcp;
    const tls = R.srv?.packet?.tlsClientHello || R.srv?.packet?.tls;
    const uaOs = R.dev?.os || "";
    if (!tcp) {
      out.conn = { level: "info", summary: "当前连接复用了既有会话，点击「重新检测」可触发全新 SYN 握手抓包" };
    } else {
      const tcpFam = tcp.osFamily || tcp.osGuess; // windows, apple, linux, unix
      const claimApple = /^(macOS|iOS|iPadOS)$/.test(uaOs);
      const claimWin = uaOs === "Windows";
      const osMismatch =
        (tcpFam === "windows" && !claimWin) ||
        (tcpFam === "apple" && !claimApple) ||
        (tcpFam === "linux" && (claimApple || claimWin));

      const hasGr = !!(tls?.hasGrease ?? tls?.grease);
      const noGrease = tls && !hasGr && R.engine === "V8";
      const tun = tcp.tunnelGuess || tcp.tunnelHint;

      if (osMismatch) {
        const tcpHuman = ({ windows: "Windows", apple: "macOS / iOS", linux: "Linux / Android" })[tcpFam] || tcp.osGuess || tcpFam;
        out.conn = { level: "bad", summary: `底层协议栈穿帮：UA 声称你在用 ${uaOs}，但替你发起 TCP 连接的机器却是 ${tcpHuman}（典型代理服务器代发连接特征）` };
      } else if (noGrease) {
        out.conn = { level: "bad", summary: `TLS 握手异常：声称为 Chromium 浏览器但缺失 GREASE 扩展，流量疑似被中间人解密重签或非原生浏览器发包` };
      } else if (tun && !["ethernet", "pppoe"].includes(tun)) {
        out.conn = { level: "warn", summary: `TCP 协议栈系统吻合，但链路 MTU=${tcp.mtu} 暴露了 VPN / 虚拟网卡隧道封装特征 (${tun})` };
      } else {
        out.conn = { level: "ok", summary: `TCP 初始 TTL=${tcp.initialTtl}、窗口选项与 TLS 指纹均与 ${uaOs || "自报系统"} 原生协议栈吻合` };
      }
    }

    // 7. synspoof: IP DF/IPID Continuity, TCP Timestamp Hz & Mux Coalescing
    const mux = R.muxBurst;
    const linuxClaimDfZero = tcp && tcp.df === false && /^(Linux|Android|HarmonyOS)$/.test(uaOs);
    if (!tcp && !mux) {
      out.synspoof = { level: "info", summary: "等待底层 IP/TCP 跨包时钟与微脉冲粘包核验…" };
    } else if (tcp?.synSpoofSuspect) {
      out.synspoof = { level: "bad", summary: `抓获无状态 SYN 改包：首包与后续数据包 TSval 时钟节拍 (${tcp.tsHz ?? "突变"}Hz) 或 IPID 序列前后断裂！` };
    } else if (linuxClaimDfZero) {
      out.synspoof = { level: "warn", summary: `IP 包头矛盾：自报 ${uaOs} 系统（默认强制 DF=1），但网卡实测首包 DF=0 允许分片` };
    } else if (mux && (mux.coalescedPairs >= 3 || (mux.srvSpanMs < mux.clientSpanMs * 0.35 && mux.clientSpanMs >= 25))) {
      out.synspoof = { level: "warn", summary: `检出隧道粘包合并：6 组 8ms 微脉冲到达服务端时出现 ${mux.coalescedPairs} 对粘包合并，疑似经过 Mux 多路复用代理` };
    } else {
      const hzInfo = tcp?.tsHz != null ? `TS 时钟≈${tcp.tsHz}Hz` : "跨包序列连续";
      out.synspoof = { level: "ok", summary: `${hzInfo}，未见无状态 SYN 伪造改包或多路复用粘包畸变` };
    }

    // 8. reality: Active :443 TLS & VLESS-Reality Stolen Certificate Back-Probe
    const t4 = R.intel?.tls443;
    if (!R.intel) {
      out.reality = { level: "info", summary: "正在对当前出口 :443 端口执行反向 TLS 握手与证书归属验真…" };
    } else if (!t4 || !t4.probed) {
      out.reality = { level: "info", summary: "当前服务端未开启 :443 主动反向回探" };
    } else if (t4.realitySuspect) {
      out.reality = { level: "bad", summary: `反向穿透实锤伪装：出口并非大厂官方 ASN，但 :443 却返回 ${t4.realityBrand || "大厂"} 证书 (${t4.realityDomain || "SNI"})，系典型 VLESS-Reality 偷证书节点！` };
    } else if (t4.tlsActive && t4.selfSignedOrIpCert) {
      out.reality = { level: "warn", summary: `出口公网 :443 开放且暴露自签/裸 IP 证书 (CN=${t4.subjectCN || "无"})，不符常规家庭宽带特征` };
    } else if (t4.port443Open && R.netKind !== "dc") {
      out.reality = { level: "warn", summary: `出口自称非机房宽带，但公网 :443 端口处于活跃监听状态 (${t4.subjectCN ? "CN=" + t4.subjectCN : "TCP 开放"})` };
    } else {
      out.reality = {
        level: "ok",
        summary: t4.tlsActive
          ? `出口 :443 证书归属正常 (CN=${t4.subjectCN || "合规"})，未见 Reality 偷证书伪装`
          : t4.port443Open
          ? "出口 :443 端口开放（无伪造大厂证书），未见 Reality 借用域名伪装"
          : "出口公网 :443 关闭或静默丢包，符合真实家庭宽带 NAT 终端特征"
      };
    }

    // 9. rtt: 3D Physical Distance Triangulation (Browser HTTP vs Server TCP vs WebRTC STUN UDP + Geo Fiber Floor)
    if (!R.latDone || R.httpRtt == null) {
      out.rtt = { level: "info", summary: R.coarseTimer ? "浏览器开启了时钟降精度保护，无法精确测量毫秒级往返差" : "等待浏览器热连接、服务端握手与 UDP 候选三维测距…" };
    } else {
      const udpBypass = R.stunRttMs != null && (R.httpRtt - R.stunRttMs) >= 75;
      if (udpBypass) {
        out.rtt = { level: "bad", summary: `UDP 旁路穿帮：HTTP TCP 往返需 ${R.httpRtt} ms，但 STUN UDP 仅 ${R.stunRttMs} ms，暴露本地宽带直连 UDP！` };
      } else if (R.srvTcpRtt != null) {
        const extra = R.httpRtt - R.srvTcpRtt;
        if (extra >= 95) {
          out.rtt = { level: "bad", summary: `物理测距抓获中转：服务端与出口握手仅 ${R.srvTcpRtt} ms，但浏览器实际往返高达 ${R.httpRtt} ms（多绕了 +${extra} ms 代理路程）` };
        } else if (extra >= 42) {
          out.rtt = { level: "warn", summary: `往返存在额外开销：浏览器往返 ${R.httpRtt} ms 比服务端握手 ${R.srvTcpRtt} ms 慢了 +${extra} ms，疑似经过代理中转` };
        } else {
          out.rtt = { level: "ok", summary: `三维测距吻合：浏览器 HTTP (${R.httpRtt} ms) 与服务端 TCP 握手 (${R.srvTcpRtt} ms) 基本一致` };
        }
      } else {
        const geoBase = expectedDirectRttMs();
        const geoExtra = geoBase ? Math.round(R.httpRtt - geoBase.expectedMs) : null;
        if (geoBase && geoExtra >= 145 && R.httpRtt >= 290) {
          out.rtt = { level: "bad", summary: `物理光速测距抓获中转：出口距服务端约 ${geoBase.km} km（直连光缆基准 ~${geoBase.expectedMs} ms），但实测热连接往返高达 ${R.httpRtt} ms（多绕 +${geoExtra} ms 代理路程）` };
        } else if (geoBase && geoExtra >= 95 && R.httpRtt >= 230) {
          out.rtt = { level: "warn", summary: `往返延迟高于地理直连基准：距服务端约 ${geoBase.km} km（直连基准 ~${geoBase.expectedMs} ms），实测 HTTP 往返 ${R.httpRtt} ms（偏慢 +${geoExtra} ms），疑似代理中转` };
        } else if (!geoBase && R.httpRtt >= 360) {
          out.rtt = { level: "bad", summary: `物理往返延迟异常：单次热连接 HTTP 往返高达 ${R.httpRtt} ms（远超全球海底光缆直连物理上限），实锤跨洲多跳代理中转` };
        } else if (!geoBase && R.httpRtt >= 270) {
          out.rtt = { level: "warn", summary: `热连接 HTTP 往返达 ${R.httpRtt} ms，显著高于常规洲际直连延迟，疑似经过代理中转` };
        } else {
          out.rtt = {
            level: "ok",
            summary: geoBase
              ? `地理光缆测距吻合：浏览器 HTTP 往返 ${R.httpRtt} ms 符合 ${geoBase.km} km 物理直连范围（基准 ~${geoBase.expectedMs} ms）`
              : `浏览器热连接 HTTP 往返 ${R.httpRtt} ms，未见跨洲中转延迟异常`
          };
        }
      }
    }

    // 10. webrtc: WebRTC STUN Leak & IPv6 MAC Leak
    const rtcList = Array.isArray(R.rtc) ? R.rtc : [];
    const knownIps = new Set([R.ip, R.stack?.v4, R.stack?.v6].filter(Boolean));
    const leakedRtc = rtcList.filter(x => !knownIps.has(x) && netPrefix(x) !== netPrefix(R.ip));
    if (R.v6mac) {
      out.webrtc = { level: "bad", summary: `高危硬件泄漏：IPv6 地址中直接编码了物理网卡 MAC 地址 (${R.v6mac})！` };
    } else if (leakedRtc.length) {
      out.webrtc = { level: "bad", summary: `WebRTC UDP 穿透泄漏了与代理出口不同的真实公网 IP：${leakedRtc.join(", ")}` };
    } else {
      out.webrtc = { level: "ok", summary: rtcList.length ? `WebRTC 反射地址 (${rtcList[0]}) 与当前出口一致，未漏真实 IP` : "WebRTC 未暴露额外公网候选地址，局域网地址已隐藏" };
    }

    // 11. dc: Multi-Source Weighted Voting Datacenter / Hosting / Proxy Check
    const hostE = R.intel?.votes?.hosting?.E || 0;
    const anonE = Math.max(R.intel?.votes?.vpn?.E || 0, R.intel?.votes?.proxy?.E || 0, R.intel?.votes?.tor?.E || 0);
    const infCls = R.intel?.asnProfile?.inferred?.cls || "";
    if (!R.srv && !R.intel && !R.netKind) {
      out.dc = { level: "info", summary: "正在融合 8 大情报源核查出口 ASN 与运营商类型…" };
    } else if (R.netKind === "dc" || hostE >= 0.55 || infCls === "hosting" || R.intel?.cidr?.x4bDatacenter) {
      const conf = hostE > 0 ? ` · 多源机房置信度 ${Math.round(hostE * 100)}%` : "";
      out.dc = { level: "bad", summary: `机房 IP 告警：当前出口 (${R.asn} · ${R.org}) 属于云服务器/数据中心网段${conf}，易触发风控拦截` };
    } else if (anonE >= 0.45 || R.intel?.cidr?.x4bVpn) {
      out.dc = { level: "warn", summary: `共享代理/VPN 标记：虽非典型机房 ASN，但多源欺诈库检出 ${Math.round(anonE * 100)}% 代理/VPN 置信度` };
    } else if (R.netKind === "relay") {
      out.dc = { level: "info", summary: "当前使用 Apple iCloud 专用代理出口，网站已知为苹果官方隐私中继" };
    } else {
      out.dc = { level: "ok", summary: `多源交叉核验通过：原生住宅/商业宽带或移动网络出口 (${R.asn} · ${R.org})` };
    }

    // 12. lease: Fake-ISP Conflict, IP Leasing Broker & Native vs Broadcast IP
    const ap = R.intel?.asnProfile;
    const cons = R.intel?.consensus;
    if (!R.intel) {
      out.lease = { level: "info", summary: "正在核查 RDAP 注册国、PeeringDB 流量画像与 IP 商业租赁记录…" };
    } else if (ap?.inferred?.conflict) {
      out.lease = { level: "bad", summary: `识破伪家宽冲突：${ap.inferred.conflict} (${R.asn || ""})` };
    } else if (ap?.rpki === "invalid") {
      out.lease = { level: "bad", summary: `BGP 路由劫持/配置异常：当前出口网段 RPKI ROA 签名校验为 INVALID` };
    } else if (ap?.lease?.leased || ap?.lease?.possible || cons?.isNative === false) {
      const parts = [];
      if (ap?.lease?.leased) parts.push("商业租赁/转售地址段");
      else if (ap?.lease?.possible) parts.push("近期子分配/疑似转租段");
      if (cons?.isNative === false) parts.push(`广播 IP (注册于 ${cons.regCountry}，广播至 ${cons.country})`);
      out.lease = { level: "warn", summary: `非纯正本土直配家宽：${parts.join(" · ")}` };
    } else {
      out.lease = { level: "ok", summary: `RIR 原生直配地址段${cons?.regCountry ? ` (${cons.regCountry})` : ""}，未见商业转租或跨国广播痕迹` };
    }

    // 13. reputation: 12 DoH DNSBLs, 15 Threat CIDRs, Shodan CVEs & /24 Dirty Neighbours
    if (!R.intel) {
      out.reputation = { level: "info", summary: "正在并发核验 12 家实时黑名单、15 份攻击网段库与同 /24 脏邻居…" };
    } else {
      const blCnt = R.intel.dnsbl?.listedCount || 0;
      const cidrHits = (R.intel.cidr?.hits || []).filter(isThreatCidrHit).length;
      const dirty = R.intel.cidr?.neighbours?.dirtyCount || 0;
      const whole = (R.intel.cidr?.neighbours?.wholeBlockListed || []).length > 0;
      const pScore = R.intel.purity?.score ?? 90;
      const pGrade = R.intel.purity?.grade || "-";
      const vulns = (R.intel.shodan?.vulns || []).length;
      const torHit = R.intel.threat?.onionoo?.isTorExit || R.intel.threat?.onionoo?.isTorRelay;
      const asnAbuse = R.intel.asnProfile?.abuseDensity?.ratio || 0;

      if (blCnt > 0 || cidrHits > 0 || whole || torHit || pScore < 52) {
        out.reputation = {
          level: "bad",
          summary: `高危信誉污染：纯净度 ${pScore}/100 (${pGrade}) · DNSBL 上榜 ${blCnt} 家 · 威胁段命中 ${cidrHits} 项${dirty ? ` · 同 /24 脏邻居 ${dirty} 个` : ""}`
        };
      } else if (dirty > 0 || vulns > 0 || asnAbuse >= 3.5 || pScore < 78) {
        out.reputation = {
          level: "warn",
          summary: `存在网段连坐或历史瑕疵：纯净度 ${pScore}/100 (${pGrade})${dirty ? ` · 同 /24 检出 ${dirty} 个黑名单脏邻居` : ""}${vulns ? ` · Shodan 暴露 ${vulns} 个 CVE` : ""}${asnAbuse >= 3.5 ? ` · 全 ASN 滥用密度 ${asnAbuse}x` : ""}`
        };
      } else {
        out.reputation = {
          level: "ok",
          summary: `出口信誉洁净：纯净度 ${pScore}/100 (${pGrade})，12 家 DNSBL、15 份威胁段与同 /24 邻居全部零污点`
        };
      }
    }

    // 14. subpixel: Cross-OS Font Rasterizer, Native Form Widgets & Scrollbar Consistency
    const fr = R.fontRast;
    const sbw = R.scrollbarW;
    if (!fr) {
      out.subpixel = { level: "info", summary: "等待跨系统字体光栅化彩边率与原生控件几何核验…" };
    } else {
      const subHits = [];
      if (uaOs === "macOS" && fr.rgbRatio >= 0.22) {
        subHits.push(`自报 macOS（已废弃次像素彩边），但 Canvas 文字暴露出 ${(fr.rgbRatio * 100).toFixed(1)}% RGB LCD 彩边渲染`);
      }
      if (uaOs === "macOS" && sbw === 17) {
        subHits.push("自报 macOS，但滚动条占位宽度为 Windows 经典 17px");
      }
      if (uaOs === "Windows" && sbw === 0 && (window.devicePixelRatio || 1) === 1 && !mq("(pointer: coarse)")) {
        subHits.push("自报桌面 Windows，但使用了 0px 悬浮滚动条（常见于 macOS 或无头精简容器）");
      }
      if (/^(macOS|iOS|iPadOS)$/.test(uaOs) && R.subpixelMode === "subpixel") {
        subHits.push("自报 Apple 系统，但字体抗锯齿探针检出非灰阶次像素通道偏移");
      }
      if (subHits.length) {
        out.subpixel = {
          level: (uaOs === "macOS" && fr.rgbRatio >= 0.22) ? "bad" : "warn",
          summary: `跨系统图形栈破绽：${subHits.join("；")}`
        };
      } else {
        out.subpixel = {
          level: "ok",
          summary: `${fr.engine}、原生表单控件几何与滚动条宽度 (${sbw ?? 0}px) 与 ${uaOs || "当前系统"} 完全吻合`
        };
      }
    }

    // 15. hwvirt: Hypervisor CPU Steal Jitter, WASM SIMD & Dedicated Hardware Video Decoders
    const steal = R.cpuBench?.stealRatio || 1;
    const simd = R.cpuBench?.simdOk;
    const hwc = Array.isArray(R.hwCodecs) ? R.hwCodecs.length : (typeof R.hwCodecs === "number" ? R.hwCodecs : null);
    if (R.gpuSoft) {
      out.hwvirt = { level: "bad", summary: "检出 SwiftShader / Basic Render 软件虚拟显卡，缺少真实物理 GPU" };
    } else if (simd === false) {
      out.hwvirt = { level: "warn", summary: "WebAssembly 128-bit SIMD 向量指令不可用，疑似受限沙箱或老旧模拟容器" };
    } else if (steal >= 7.5 && hwc != null && hwc === 0) {
      out.hwvirt = { level: "bad", summary: `重度云主机虚拟化特征：CPU 调度抢占抖动达 ${steal}x 且 4 大主流视频硬解芯片全数为 0` };
    } else if (steal >= 6.0 || (hwc != null && hwc === 0 && /^(macOS|Windows)$/.test(uaOs))) {
      out.hwvirt = {
        level: "warn",
        summary: hwc === 0
          ? `缺少专用视频硬解芯片支持 (0/4)，疑似运行于无直通显卡的虚拟机或远程云桌面`
          : `CPU 紧致微基准尾延迟比偏高 (p98/p50=${steal}x)，存在宿主机调度抢占抖动`
      };
    } else {
      out.hwvirt = {
        level: "ok",
        summary: `物理硬件特征自然：WASM SIMD 正常${hwc != null ? ` · ${hwc}/4 项视频硬解芯片就绪` : ""} · 抢占抖动比 ${steal}x`
      };
    }

    // 16. tamper: Environment Tampering & Native Prototype Lies
    const tamperReasons = [];
    const hdrUa = R.srv?.headers?.["user-agent"] || "";
    const hdrLang = ((R.srv?.headers?.["accept-language"] || "").split(",")[0] || "").split(";")[0].trim().toLowerCase();
    if (hdrUa && navigator.userAgent && hdrUa !== navigator.userAgent) tamperReasons.push("HTTP User-Agent 头与 JS navigator.userAgent 不一致");
    if (hdrLang && R.langs?.[0] && hdrLang !== R.langs[0].toLowerCase()) tamperReasons.push(`HTTP 语言头 (${hdrLang}) 与 JS 语言 (${R.langs[0]}) 不一致`);
    if (R.tzOff != null && R.dateOff != null && R.tzOff !== R.dateOff) tamperReasons.push("Date 时区偏移与 Intl 时区相互矛盾");
    if (R.osFontMismatch) tamperReasons.push(R.osFontMismatch);
    if ((R.iframeDiffs || []).length) tamperReasons.push(`洁净 iframe 沙箱读数差异 (${R.iframeDiffs.join(", ")})`);
    if ((R.lies || []).length) tamperReasons.push(`原生接口被重写 (${R.lies.slice(0, 3).join(", ")}${R.lies.length > 3 ? ` 等 ${R.lies.length} 处` : ""})`);
    if (R.engine === "V8" && !navigator.brave && R.br?.name !== "Brave" && (R.pxNoise || R.auNoise)) {
      tamperReasons.push(`检出非原生 ${R.pxNoise ? "Canvas 像素" : "Audio 音频"}篡改噪声`);
    }
    const wantEngine = /^(iOS|iPadOS)$/.test(R.dev?.os || "") || R.br?.name === "Safari" ? "JavaScriptCore" : R.br?.name === "Firefox" ? "SpiderMonkey" : /^(Chrome|Edge|Opera|Brave|Vivaldi)$/.test(R.br?.name || "") ? "V8" : null;
    if (wantEngine && R.engine && R.engine !== "Unknown" && R.engine !== wantEngine) {
      tamperReasons.push(`自报 ${R.br?.name} 但真实 JS 引擎却是 ${R.engine}`);
    }

    if (!tamperReasons.length) {
      out.tamper = { level: "ok", summary: "52 项原生原型、HTTP 请求头、洁净 iframe 与像素回读均纯净无篡改痕迹" };
    } else {
      const severe = tamperReasons.length >= 2 || (R.lies || []).length >= 2 || (R.iframeDiffs || []).length > 0 || R.tzOff !== R.dateOff || (hdrUa && hdrUa !== navigator.userAgent);
      out.tamper = { level: severe ? "bad" : "warn", summary: `抓获环境篡改痕迹：${tamperReasons.join("；")}` };
    }

    // 17. fpb: Anti-Detect Browser & Cross-Thread Contradictions
    const fpbHits = [];
    if ((R.workerDiff || []).length) fpbHits.push(`主线程与 Web Worker 读数不一致 (${R.workerDiff.join(", ")})`);
    const claimedChrome = +((/Chrome\/(\d+)/.exec(navigator.userAgent) || [])[1] || 0);
    if (R.engine === "V8" && claimedChrome >= 115) {
      const maxTestedFloor = JS_FEATURES.filter(([v]) => v <= claimedChrome).map(([v]) => v).pop() || 0;
      if (maxTestedFloor && R.engVer < maxTestedFloor) {
        fpbHits.push(`虚报 Chrome ${claimedChrome}，但 V8 语法特性仅停留在 Chromium ${R.engVer || "<97"}`);
      } else if (R.cssv?.miss && claimedChrome >= R.cssv.miss + 2) {
        fpbHits.push(`虚报 Chrome ${claimedChrome}，但 Blink 渲染引擎缺失 Chrome ${R.cssv.miss} 的 CSS 特性`);
      }
    }
    const plat = navigator.platform || "";
    if ((R.dev?.os === "macOS" && /^Win|^Linux/i.test(plat)) || (R.dev?.os === "Windows" && /^Mac|^Linux/i.test(plat))) {
      fpbHits.push(`navigator.platform (${plat}) 与系统 (${R.dev.os}) 自相矛盾`);
    }
    const gpuOs = inferGpuOS(R.gpuRaw);
    if ((gpuOs === "Windows" && R.dev?.os && R.dev.os !== "Windows") || (gpuOs === "Apple" && R.dev?.os && !/^(macOS|iOS|iPadOS)$/.test(R.dev.os))) {
      fpbHits.push(`显卡驱动渲染栈属于 ${gpuOs}，却声称运行在 ${R.dev.os}`);
    }
    if (R.dev?.os === "macOS" && R.engine === "V8") {
      const pvRaw = String(R.hi?.platformVersion || "").trim();
      const pvMaj = pvRaw ? parseInt(pvRaw, 10) : NaN;
      const isAppleSil = /Apple M\d/i.test(R.gpuClean || R.gpuRaw || "");
      if (window.isSecureContext && claimedChrome >= 95 && !navigator.userAgentData) {
        fpbHits.push(`自称桌面 Chrome ${claimedChrome}，但缺失 Chromium 原生 navigator.userAgentData 接口`);
      } else if (!Number.isNaN(pvMaj) && pvMaj > 0 && pvMaj <= 10 && isAppleSil) {
        fpbHits.push(`硬件时空穿帮：显卡为 ${R.gpuClean}（出厂最低 macOS 11+），但高熵 Client Hints 却自报仅支持 Intel 的 macOS ${pvRaw}`);
      } else if (!Number.isNaN(pvMaj) && pvMaj > 0 && pvMaj <= 10 && claimedChrome >= 129) {
        fpbHits.push(`系统与内核版本矛盾：Chrome ${claimedChrome} 早已停止支持 macOS 10.15，但高熵平台版本仍伪装为 ${pvRaw}`);
      } else if (!pvRaw && window.isSecureContext && claimedChrome >= 110 && isAppleSil) {
        fpbHits.push(`高熵 Client Hints 异常：自称 Chrome ${claimedChrome} + ${R.gpuClean}，但 platformVersion 为空导致系统回退暴露为冻结的 macOS 10.15`);
      }
    }
    if (R.gpuSoft) fpbHits.push("使用 SwiftShader / Basic Render 软件虚拟显卡");

    out.fpb = fpbHits.length
      ? { level: "bad", summary: `识别出指纹浏览器/虚拟机硬伤：${fpbHits.join("；")}` }
      : { level: "ok", summary: "内核版本语法、Worker 线程、显卡渲染栈与平台属性完全自洽" };

    // 18. ua: UA vs Client Hints vs GPU Platform Consistency
    const hiPlat = R.hi?.platform || "";
    const hdrPlat = (R.srv?.headers?.["sec-ch-ua-platform"] || "").replace(/"/g, "");
    const uaMismatch = [];
    if (hiPlat && R.dev?.os && ((hiPlat === "Windows" && R.dev.os !== "Windows") || (hiPlat === "macOS" && R.dev.os !== "macOS") || (hiPlat === "Linux" && !/Linux|Android|HarmonyOS/.test(R.dev.os)))) {
      uaMismatch.push(`高熵 Client Hints (${hiPlat}) 与 UA (${R.dev.os}) 不符`);
    }
    if (hdrPlat && R.dev?.os && ((hdrPlat === "Windows" && R.dev.os !== "Windows") || (hdrPlat === "macOS" && R.dev.os !== "macOS"))) {
      uaMismatch.push(`HTTP Sec-CH-UA-Platform 头 (${hdrPlat}) 与 UA 不符`);
    }
    out.ua = uaMismatch.length
      ? { level: "bad", summary: uaMismatch.join("；") }
      : { level: "ok", summary: `User-Agent、Client Hints 与硬件平台 (${R.osLabel || "未知"}) 三方一致` };

    // 19. bot: Automation & Headless Browser
    out.bot = (R.botHits || []).length
      ? { level: "bad", summary: `检出自动化控制框架特征：${R.botHits.join(" · ")}` }
      : { level: "ok", summary: "未发现 WebDriver、CDP 注入钩子或无头浏览器特征" };

    // 20. fp: Cross-Site Tracking Resistance & Partial Storage Wipe / ETag Resurrection
    const protectedFp = ["brave", "rfp", "fpp", "atfp"].includes(R.shieldKind);
    const lsCleared = !R.traceSurvived || !R.traceSurvived.includes("LocalStorage");
    const cacheResurrected = lsCleared && (!!R.etag?.seen || (R.traceSurvived || []).length > 0);
    R.cacheResurrected = cacheResurrected;

    if (cacheResurrected) {
      out.fp = {
        level: "bad",
        summary: R.etag?.seen
          ? `防关联隔离穿帮：已清空本地存储试图伪装新访客，但浏览器 HTTP ETag 缓存 (${R.etag.id.slice(0, 8)}) 仍直接认出老身份！`
          : `防关联残留复活：LocalStorage 虽已清除，但 ${R.traceSurvived.join(" / ")} 仍保留旧标记 (${R.traceTag})！`
      };
    } else if (protectedFp) {
      out.fp = { level: "ok", summary: `已受 ${R.shieldLabel} 保护，跨站静态指纹已被动态打散` };
    } else if (R.etag?.seen || (R.traceSurvived || []).length > 1) {
      out.fp = { level: "bad", summary: `无防指纹保护且已被缓存 ETag / 多重存储跨会话锁定 (硬件码 ${R.hwId})` };
    } else {
      out.fp = { level: "warn", summary: `画布、音频与硬件指纹完全固定 (${R.fpId})，网站无需 Cookie 即可跨站认出你` };
    }

    // 4 Protocol Checks (Informational / Transport Diagnostics)
    const edgeKex = R.cfEdge?.kex || "";
    const pqOk = R.srvPq || /MLKEM|Kyber/i.test(edgeKex);
    out.pq = {
      level: pqOk ? "ok" : "info",
      summary: pqOk ? `已启用抗量子混合密钥交换 (${R.srvPqGroup || edgeKex})` : "当前连接使用传统椭圆曲线密钥交换 (X25519)"
    };
    const echOk = R.srvEch || R.cfEdge?.sni === "encrypted";
    out.ech = {
      level: echOk ? "ok" : "info",
      summary: echOk ? "TLS ClientHello 已启用 ECH 加密域名保护" : "当前连接发送明文 SNI 域名（常规状态，不影响伪装评分）"
    };
    out.h3 = {
      level: R.hasH3 ? "ok" : "info",
      summary: R.hasH3 ? "UDP 443 畅通，浏览器已成功建立 HTTP/3 (QUIC) 连接" : "当前走 TCP HTTP/2（多数代理节点未转发 UDP 443 QUIC，属常见现象）"
    };
    const warpVal = R.cfEdge?.warp || "off";
    out.warp = {
      level: warpVal !== "off" ? "ok" : "info",
      summary: warpVal !== "off" ? `流量正经过 Cloudflare WARP (${warpVal}) 加密隧道` : "未使用 Cloudflare WARP / Zero Trust 网关"
    };

    R.checks = out;
    return out;
  }

  function isCheckCounted(id) {
    const def = CORE_CHECKS.find(c => c[0] === id);
    if (!def) return false;
    if (currentScene === "privacy") {
      return ["webrtc", "dns", "fp", "fpb", "tamper", "bot"].includes(id);
    }
    if (id === "fp" && R.cacheResurrected) return true;
    return def[2].includes("disguise");
  }

  function renderChecksAndScore(recordHistory = false) {
    const checks = evaluateAllChecks();
    let badCnt = 0, warnCnt = 0, okCnt = 0, unverifiedCnt = 0, penalty = 0;

    const styleMap = {
      ok: {
        badgeCls: "bg-teal-100 text-teal-700 dark:bg-teal-500/20 dark:text-teal-400",
        badgeTxt: "✓",
        segCls: "bg-teal-500",
        tagCls: "bg-teal-50 text-teal-700 dark:bg-teal-500/10 dark:text-teal-400",
        tagTxt: "通过"
      },
      warn: {
        badgeCls: "bg-amber-100 text-amber-700 dark:bg-amber-500/20 dark:text-amber-400",
        badgeTxt: "!",
        segCls: "bg-amber-500",
        tagCls: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400",
        tagTxt: "可疑破绽"
      },
      bad: {
        badgeCls: "bg-red-100 text-red-700 dark:bg-red-500/20 dark:text-red-400",
        badgeTxt: "✕",
        segCls: "bg-red-500",
        tagCls: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400",
        tagTxt: "高危暴露"
      },
      info: {
        badgeCls: "bg-gray-100 text-gray-500 dark:bg-neutral-800 dark:text-neutral-400",
        badgeTxt: "i",
        segCls: "bg-gray-300 dark:bg-neutral-700",
        tagCls: "bg-gray-100 text-gray-600 dark:bg-neutral-800 dark:text-neutral-400",
        tagTxt: "提示"
      }
    };

    const RETESTABLE = new Set(["tz", "lang", "syslang", "dns", "split", "conn", "synspoof", "reality", "rtt", "webrtc", "dc", "lease", "reputation", "subpixel", "hwvirt"]);
    const TIMEOUT_SENSITIVE = new Set(["tz", "lang", "split", "reality", "rtt", "dc", "lease", "reputation"]);

    for (const [id] of [...CORE_CHECKS, ...PROTO_CHECKS]) {
      const row = CHECK_EL[id];
      const res = checks[id] || { level: "info", summary: "–" };
      const st = styleMap[res.level] || styleMap.info;
      const isCore = CORE_CHECKS.some(c => c[0] === id);
      const active = !isCore || isCheckCounted(id);

      if (isCore && active) {
        if (res.level === "bad") { badCnt++; penalty += (CHECK_WEIGHTS[id] || 6) * 1.85; }
        else if (res.level === "warn") { warnCnt++; penalty += (CHECK_WEIGHTS[id] || 5) * 0.95; }
        else if (res.level === "ok") { okCnt++; }
        else if (
          TIMEOUT_SENSITIVE.has(id) &&
          !(id === "dc" && R.netKind === "relay") &&
          !(id === "reality" && R.intel && !R.intel.tls443?.probed) &&
          !(id === "rtt" && R.coarseTimer)
        ) {
          unverifiedCnt++;
        }
      }

      // Segment bar update (keep flex-1 for 20-segment flex bar)
      const seg = $(`#segBar [data-seg="${id}"]`);
      if (seg) {
        seg.className = `flex-1 h-full rounded-full transition-colors ${active ? st.segCls : "bg-gray-200 opacity-40 dark:bg-neutral-800"}`;
      }

      if (!row) continue;
      row.classList.toggle("opacity-50", isCore && !active);

      // Apply filter visibility
      const isIssue = res.level === "bad" || res.level === "warn";
      const hideByFilter = (checkFilter === "issues" && !isIssue) || (checkFilter === "ok" && res.level !== "ok");
      row.hidden = hideByFilter;

      const badge = $(".ck-badge", row);
      if (badge) {
        badge.className = `ck-badge mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${st.badgeCls}`;
        badge.textContent = st.badgeTxt;
      }
      const tag = $(".ck-tag", row);
      if (tag) {
        tag.className = `ck-tag inline-flex py-0.5 px-1.5 rounded text-[10px] font-medium ${st.tagCls}`;
        tag.textContent = isCore && !active ? "当前视角不计分" : st.tagTxt;
      }
      const val = $(".ck-val", row);
      if (val) {
        val.textContent = res.summary;
        val.className = "ck-val maskable mt-0.5 text-xs leading-relaxed " + (
          res.level === "bad" ? "text-red-700 font-medium dark:text-red-300"
            : res.level === "warn" ? "text-amber-800 font-medium dark:text-amber-300"
            : "text-gray-600 dark:text-neutral-400"
        );
      }

      const btnHow = $(".ck-howto", row);
      if (btnHow) btnHow.textContent = isIssue ? "怎么改 ▾" : "原理";

      const btnRe = $(".ck-retest", row);
      if (btnRe) btnRe.hidden = !(R.finished && RETESTABLE.has(id));

      const drawer = $(".ck-drawer", row);
      if (drawer) {
        const steps = getFixSteps(id);
        drawer.innerHTML = `<ul class="list-disc ps-4 space-y-1">${steps.map(s => `<li>${esc(s)}</li>`).join("")}</ul>`;
      }
    }

    // Fail-closed uncertainty penalty: 超时未完成核验的核心网络项绝不能当作 0 扣分白送 A+！
    if (R.finished && unverifiedCnt > 0) {
      penalty += unverifiedCnt * 5.5 + (!R.ipCC ? 14 : 0);
    }

    const score = Math.max(5, Math.min(100, Math.round(100 - penalty)));
    let grade = score >= 92 && badCnt === 0 ? "A+" : score >= 85 && badCnt === 0 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 42 ? "D" : "F";
    if (R.finished && unverifiedCnt > 0) {
      if (!R.ipCC || unverifiedCnt >= 5) {
        if (grade === "A+" || grade === "A" || grade === "B") grade = "C";
      } else if (unverifiedCnt >= 2) {
        if (grade === "A+" || grade === "A") grade = "B";
      } else if (grade === "A+") {
        grade = "A";
      }
    }
    const totalIssues = badCnt + warnCnt;

    R.score = score;
    R.grade = grade;
    R.totalIssues = totalIssues;
    R.unverifiedCnt = unverifiedCnt;

    $("#scoreNum").textContent = String(score);
    const gBadge = $("#gradeBadge");
    if (gBadge) {
      gBadge.textContent = `等级 ${grade}`;
      gBadge.className = "inline-flex items-center gap-x-1 py-0.5 px-2.5 rounded-full text-xs font-semibold " + (
        /^A/.test(grade) ? "bg-teal-50 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400"
          : grade === "B" || grade === "C" ? "bg-amber-50 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400"
          : "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400"
      );
    }
    $("#scoreSub").textContent = totalIssues === 0 && R.finished && unverifiedCnt > 0
      ? `有 ${unverifiedCnt} 项网络情报探针超时未完成核验，已按风控不确定性降级评分`
      : totalIssues === 0
      ? "当前网络信誉、底层协议栈与系统指纹高度自洽"
      : badCnt > 0
      ? `检出 ${badCnt} 项高危穿帮与 ${warnCnt} 项可疑信号，易触发风控验证`
      : `无硬性矛盾，但有 ${warnCnt} 项环境细节存在轻微破绽`;

    $("#issueCount").textContent = String(totalIssues);
    $("#issueCount").className = "text-3xl font-bold tracking-tight font-mono tabular-nums " + (
      badCnt > 0 ? "text-red-600 dark:text-red-400"
        : (warnCnt > 0 || (R.finished && unverifiedCnt > 0)) ? "text-amber-600 dark:text-amber-400"
        : "text-teal-600 dark:text-teal-400"
    );
    $("#cntBad").textContent = String(badCnt);
    $("#cntWarn").textContent = String(warnCnt);
    $("#cntOk").textContent = String(okCnt);
    $("#sceneBadge").textContent = currentScene === "privacy" ? "隐私防追踪视角" : "伪装自检视角";

    // Priority Top-3 Fixes ("先改这几项")
    const rankedIssues = CORE_CHECKS
      .map(([id, title]) => ({ id, title, lv: checks[id]?.level }))
      .filter(x => isCheckCounted(x.id) && (x.lv === "bad" || x.lv === "warn"))
      .sort((a, b) => (a.lv === "bad" ? 0 : 1) - (b.lv === "bad" ? 0 : 1) || (CHECK_WEIGHTS[b.id] || 0) - (CHECK_WEIGHTS[a.id] || 0));

    $("#topGiveaway").textContent = rankedIssues.length
      ? `头号暴露项：${rankedIssues[0].title}`
      : (R.finished && unverifiedCnt > 0)
      ? `已通过 ${okCnt} 项 · ${unverifiedCnt} 项网络探针超时未核验（可点对应行重测）`
      : `${CORE_CHECKS.filter(c => isCheckCounted(c[0])).length} 项计分风控核验全部通过`;

    const pBox = $("#priorityBox"), pList = $("#priorityList");
    if (pBox && pList) {
      if (!rankedIssues.length) {
        pBox.hidden = true;
      } else {
        pBox.hidden = false;
        pList.innerHTML = rankedIssues.slice(0, 3).map((item, idx) => {
          const firstStep = getFixSteps(item.id)[0] || "";
          return `
            <li class="flex items-start gap-2.5">
              <span class="mt-0.5 inline-flex size-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold ${item.lv === "bad" ? "bg-red-600 text-white" : "bg-amber-500 text-white"}">${idx + 1}</span>
              <button type="button" data-jumpck="${esc(item.id)}" class="text-left group min-w-0 flex-1">
                <span class="font-semibold text-gray-900 group-hover:text-blue-600 dark:text-white dark:group-hover:text-blue-400">${esc(item.title)}：</span>
                <span class="text-gray-700 dark:text-neutral-300">${esc(firstStep)}</span>
              </button>
            </li>
          `;
        }).join("");
      }
    }

    renderScenarios();

    // Run-over-run comparison & sparkline
    if (recordHistory) {
      let prev = null;
      try { prev = JSON.parse(store.get(SK.prevChecks) || "null"); } catch (e) {}
      store.set(SK.prevChecks, JSON.stringify({ at: Date.now(), issues: totalIssues, score }));
      const cmpEl = $("#cmpBadge");
      if (cmpEl && prev && typeof prev.issues === "number") {
        const d = totalIssues - prev.issues;
        cmpEl.hidden = false;
        cmpEl.textContent = d === 0 ? "与上次持平" : d < 0 ? `比上次少 ${Math.abs(d)} 处破绽 ↓` : `比上次多 ${d} 处破绽 ↑`;
        cmpEl.className = "text-[11px] font-medium px-2 py-0.5 rounded-md whitespace-nowrap " + (
          d < 0 ? "bg-teal-50 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400"
            : d > 0 ? "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400"
            : "bg-gray-100 text-gray-600 dark:bg-neutral-800 dark:text-neutral-300"
        );
      }

      let hist = [];
      try { hist = JSON.parse(store.get(SK.history) || "[]"); } catch (e) {}
      hist = [...(Array.isArray(hist) ? hist : []), { t: Date.now(), s: score }].slice(-10);
      store.set(SK.history, JSON.stringify(hist));
      const spk = $("#histSpark");
      if (spk && hist.length >= 2) {
        spk.hidden = false;
        const W = 80, H = 24;
        const pts = hist.map((p, i) => `${((i * W) / (hist.length - 1)).toFixed(1)},${(H - 3 - (p.s / 100) * (H - 6)).toFixed(1)}`).join(" ");
        spk.innerHTML = `<svg viewBox="0 0 ${W} ${H}" class="w-full h-full stroke-blue-600 dark:stroke-blue-400 fill-none" stroke-width="1.7"><polyline points="${pts}"/></svg>`;
      }
    }
  }

  /* ---------- 6 Business Scenario Suitability Meters (Fusing Egress Intel + Browser Checks) ---------- */
  function computeScenarios() {
    const intel = R.extIntel || R.intel;
    const isExt = !!(R.extIntel && R.extIntel.ok);
    const ck = isExt ? {} : (R.checks || {});

    const cc = (intel?.consensus?.country || R.ipCC || "").toUpperCase();
    const isNative = intel?.consensus?.isNative;
    const hostE = intel?.votes?.hosting?.E ?? (R.netKind === "dc" ? 0.85 : 0.05);
    const vpnE = intel?.votes?.vpn?.E || 0;
    const proxyE = intel?.votes?.proxy?.E || 0;
    const torE = intel?.votes?.tor?.E || 0;
    const maxAnon = Math.max(vpnE, proxyE, torE);
    const infCls = intel?.asnProfile?.inferred?.cls || (R.netKind === "dc" ? "hosting" : "isp");
    const asnConflict = !!intel?.asnProfile?.inferred?.conflict;
    const isHosting = hostE >= 0.55 || infCls === "hosting" || !!intel?.cidr?.x4bDatacenter || (!intel && R.netKind === "dc");
    const isLeased = !!(intel?.asnProfile?.lease?.leased || intel?.asnProfile?.lease?.possible);
    const realityHit = !!intel?.tls443?.realitySuspect;
    const blCnt = intel?.dnsbl?.listedCount || 0;
    const cidrHits = (intel?.cidr?.hits || []).filter(isThreatCidrHit).length;
    const dirty = intel?.cidr?.neighbours?.dirtyCount || 0;
    const wholeBlock = (intel?.cidr?.neighbours?.wholeBlockListed || []).length > 0;
    const asnAbuse = intel?.asnProfile?.abuseDensity?.ratio || 0;
    const sfsHit = !!(intel?.threat?.sfs?.appears);
    const hasPtr = !!(intel?.consensus?.hostname || (intel?.shodan?.hostnames || []).length);
    const rpkiInvalid = intel?.asnProfile?.rpki === "invalid";

    const mk = (base, rules) => {
      let s = base;
      const reasons = [];
      for (const [cond, pts, msg] of rules) {
        if (cond) { s -= pts; reasons.push(msg); }
      }
      const score = Math.max(5, Math.min(100, Math.round(s)));
      return {
        score,
        reason: reasons[0] || "出口纯净且环境特征自然契合"
      };
    };

    const aiBlockedCC = ["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY"].includes(cc);
    const aiSplitLeak = !isExt && (["CN", "HK", "MO"].includes(R.exits?.ex_gpt?.cc || "") || ["CN", "HK", "MO"].includes(R.exits?.ex_claude?.cc || ""));

    return {
      ai: mk(98, [
        [aiBlockedCC, 68, `${cc || "当前地区"} 不在主流海外 AI 官方服务支持区`],
        [aiSplitLeak, 45, "AI 专属分流规则落入受限地区 (CN/HK)"],
        [torE >= 0.4, 38, "Tor 出口易触发大模型高频拒访"],
        [realityHit, 22, "出口 :443 暴露 Reality 偷证书节点特征"],
        [isHosting, 22, "机房 IDC 段易触发 ChatGPT 降智或 Claude 封号"],
        [maxAnon >= 0.45, 16, "共享 VPN/代理出口易弹 PoW 算力验证"],
        [blCnt > 0 || cidrHits > 0, 14, "命中公开威胁/黑名单库"],
        [ck.tz?.level === "bad", 12, "系统时区与出口国家严重不符"]
      ]),
      streaming: mk(98, [
        [cc === "CN", 65, "中国大陆出口无法直接解锁海外流媒体库"],
        [isHosting, 30, "机房 ASN 通常被 Netflix / Disney+ 归入代理库仅放行自制剧"],
        [isNative === false, 26, `广播 IP (${intel?.consensus?.regCountry}→${cc}) 易跨区识别偏差或锁区`],
        [maxAnon >= 0.4 || intel?.cidr?.x4bVpn, 22, "命中商业 VPN/代理特征库"],
        [asnConflict || isLeased, 15, "伪家宽或商业转租段易被流媒体版权库降级"],
        [ck.tz?.level === "bad" || ck.split?.level === "bad", 16, "时区/国内分流破绽影响 TikTok 推荐池定位"]
      ]),
      social: mk(97, [
        [isHosting, 32, "机房 IP 注册 X / Reddit / IG 极易秒冻或强制短信验证"],
        [maxAnon >= 0.4 || realityHit, 24, "共享代理或 Reality 节点易触发批量关联风控"],
        [blCnt > 0 || cidrHits > 0 || sfsHit, 22, "存在垃圾注册或黑名单不良历史"],
        [dirty >= 3 || asnAbuse >= 4, 15, `同 /24 存在 ${dirty} 个脏邻居连坐污染`],
        [ck.fpb?.level === "bad" || ck.tamper?.level === "bad", 22, "浏览器存在防关联插件/跨线程篡改痕迹"],
        [ck.conn?.level === "bad", 14, "底层 TCP 协议栈暴露代理服务器代发连接"]
      ]),
      captcha: mk(98, [
        [blCnt > 0 || cidrHits > 0 || wholeBlock, 36, "命中实时黑名单或整段封禁，必弹交互式验证盾"],
        [ck.bot?.level === "bad", 35, "暴露 WebDriver / 自动化控制特征"],
        [ck.tamper?.level === "bad", 22, "JS 原型篡改直接拉低 Turnstile 信任分"],
        [isHosting, 18, "机房 ASN 默认初始人机信任分较低"],
        [maxAnon >= 0.45 || realityHit, 16, "匿名代理出口易触发循环点选验证码"],
        [dirty >= 4, 14, `同 /24 网段含 ${dirty} 个脏邻居拖累免盾率`],
        [ck.conn?.level === "bad", 10, "TLS / TCP 握手栈与自报系统不一致"]
      ]),
      fintech: mk(98, [
        [isHosting || asnConflict, 38, "支付反欺诈引擎（如 Stripe Radar）对机房/伪家宽严厉拒付"],
        [maxAnon >= 0.35 || realityHit, 28, "检出代理/VPN 或 :443 伪装特征，高危拒付风险"],
        [isLeased || isNative === false, 20, "租赁或跨国广播 IP 极易触发账单地址人工审核"],
        [blCnt > 0 || cidrHits > 0 || dirty >= 5, 22, "网段存在欺诈或黑名单不良记录"],
        [ck.webrtc?.level === "bad" || ck.dns?.level === "bad" || ck.split?.level === "bad", 25, "真实 IP / DNS 分流泄漏直接触发异地盗刷拦截"],
        [ck.tz?.level === "bad" || ck.rtt?.level === "bad", 16, "物理往返延迟或系统时区与账单国矛盾"]
      ]),
      email: mk(96, [
        [blCnt > 0, 48, `已上榜 ${blCnt} 家实时 DNSBL 黑名单，25 端口发信直接拒收`],
        [wholeBlock || dirty >= 5, 25, `同 /24 网段含 ${dirty} 个发信污点邻居，极易进垃圾箱`],
        [cidrHits > 0 || sfsHit, 22, "命中公开垃圾邮件或攻击源威胁库"],
        [infCls === "isp" || infCls === "mobile", 16, "民用宽带/移动网段通常封禁 25 端口并列入 Spamhaus PBL"],
        [!hasPtr, 12, "当前 IP 缺少反向 PTR (rDNS) 域名解析记录"],
        [rpkiInvalid, 15, "BGP RPKI 路由签名无效，降低大型邮局信任度"]
      ])
    };
  }

  function renderScenarios() {
    if (!R.srv && !R.intel && !R.extIntel && !R.ipCC && !R.finished) return;
    const sc = computeScenarios();
    R.scenarios = sc;
    let passCnt = 0;
    for (const [id] of SCENARIOS_META) {
      const card = $(`#scenarioGrid [data-scen="${id}"]`);
      const item = sc[id];
      if (!card || !item) continue;
      const ok = item.score >= 80;
      const warn = item.score >= 55 && item.score < 80;
      if (ok) passCnt++;

      card.className = "rounded-lg border p-3 flex flex-col justify-between gap-2 transition " + (
        ok ? "border-teal-200/80 bg-teal-50/30 dark:bg-teal-500/5 dark:border-teal-500/20"
          : warn ? "border-amber-200/80 bg-amber-50/30 dark:bg-amber-500/5 dark:border-amber-500/20"
          : "border-red-200/80 bg-red-50/30 dark:bg-red-500/5 dark:border-red-500/20"
      );
      const badge = $(".sc-badge", card);
      if (badge) {
        badge.textContent = ok ? "畅通推荐" : warn ? "受限/易验" : "高危劝退";
        badge.className = "sc-badge inline-flex items-center py-0.5 px-1.5 rounded text-[10px] font-semibold shrink-0 " + (
          ok ? "bg-teal-100 text-teal-800 dark:bg-teal-500/20 dark:text-teal-300"
            : warn ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300"
            : "bg-red-100 text-red-800 dark:bg-red-500/20 dark:text-red-300"
        );
      }
      const sEl = $(".sc-score", card);
      if (sEl) {
        sEl.textContent = String(item.score);
        sEl.className = "sc-score font-mono text-lg font-bold tabular-nums " + (
          ok ? "text-teal-700 dark:text-teal-400" : warn ? "text-amber-700 dark:text-amber-400" : "text-red-600 dark:text-red-400"
        );
      }
      const bar = $(".sc-bar", card);
      if (bar) {
        bar.style.width = `${item.score}%`;
        bar.className = "sc-bar h-full rounded-full transition-all duration-300 " + (
          ok ? "bg-teal-500" : warn ? "bg-amber-500" : "bg-red-500"
        );
      }
      const rEl = $(".sc-reason", card);
      if (rEl) rEl.textContent = item.reason;
    }

    const sumBadge = $("#scenarioSummaryBadge");
    if (sumBadge) {
      sumBadge.textContent = `${passCnt} / ${SCENARIOS_META.length} 个主流场景畅通达标`;
      sumBadge.className = "inline-flex items-center py-0.5 px-2.5 rounded-full text-xs font-medium " + (
        passCnt >= 5 ? "bg-teal-50 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400"
          : passCnt >= 3 ? "bg-amber-50 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400"
          : "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400"
      );
    }
  }

  /* ---------- Forensic Identity Portrait ("网站眼里的你") ---------- */
  function chip(text, probeIds = [], tone = "default", mask = false) {
    const cls = tone === "bad"
      ? "bg-red-50 text-red-700 border-red-200 dark:bg-red-500/15 dark:text-red-300 dark:border-red-500/30"
      : tone === "warn"
      ? "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-500/15 dark:text-amber-300 dark:border-amber-500/30"
      : tone === "ok"
      ? "bg-teal-50 text-teal-700 border-teal-200 dark:bg-teal-500/15 dark:text-teal-300 dark:border-teal-500/30"
      : "bg-blue-50/80 text-blue-800 border-blue-200/80 dark:bg-blue-500/15 dark:text-blue-300 dark:border-blue-500/30";
    return `<button type="button" data-from="${esc(probeIds.join(","))}" class="${mask ? "maskable " : ""}probe-chip inline-flex items-center px-1.5 py-0.5 mx-0.5 rounded-md border text-[12.5px] font-semibold leading-snug align-baseline cursor-pointer hover:ring-2 hover:ring-blue-400/50 transition ${cls}">${esc(text)}</button>`;
  }

  function renderPortrait() {
    const checks = R.checks || {};
    const sys = inferSystemLangs({ os: R.dev?.os, sysFonts: R.fonts || [], voices: R.voices || [], kbd: R.kbd });
    const origin = inferOrigin({
      langs: R.langs || [],
      tz: R.tz,
      ipcc: R.ipCC,
      sys,
      ios: /^(iOS|iPadOS)$/.test(R.dev?.os || "")
    });

    // Check if Mainland China direct route exposed exact province/city
    const cnLeak = R.exits?.ex_cn?.cc === "CN" && R.ipCC && R.ipCC !== "CN" ? R.exits.ex_cn.label : null;
    const originText = cnLeak
      ? `中国大陆 (${cnLeak})`
      : origin?.cc
      ? `${flagEmoji(origin.cc)} ${countryName(origin.cc)}用户`
      : "未知来源地区";

    const exitCity = R.srv?.geo?.city || R.ipCity || R.intel?.consensus?.city || "";
    const exitText = R.ipCC ? `${flagEmoji(R.ipCC)} ${[exitCity, countryName(R.ipCC)].filter(Boolean).join(", ")}（按 IP 估）` : (R.finished ? "出口查询超时" : "读取中…");

    // Snapshot 4-Grid
    $("#snapOrigin").textContent = originText;
    $("#snapExit").textContent = exitText;
    $("#snapDevice").textContent = `${R.osLabel || "未知系统"} · ${R.physScreen || "–"} @ ${R.hz || 60}Hz`;
    $("#snapGpu").textContent = R.gpuDiscrete ? `${R.gpuDiscrete} + ${R.gpuClean}` : (R.gpuClean || "未知显卡");

    // Headline Critical Giveaway Alert Banner (#wowAlert)
    const wowEl = $("#wowAlert"), wowIcon = $("#wowIcon"), wowTitle = $("#wowTitle"), wowDesc = $("#wowDesc");
    if (wowEl && wowTitle && wowDesc && wowIcon) {
      let alertTone = "ok", head = "底层协议栈、网络出口信誉与浏览器环境自洽", sub = "未发现代理代发连接、Reality 偷证书、国内直连漏底或浅层篡改插件留下的致命硬伤。";
      if (checks.reality?.level === "bad") {
        alertTone = "bad";
        head = "最要命的一条：反向 :443 穿透抓获 Reality 偷证书伪装";
        sub = checks.reality.summary;
      } else if (checks.conn?.level === "bad") {
        alertTone = "bad";
        head = "最要命的一条：底层 TCP 协议栈与自报系统直接打架";
        sub = checks.conn.summary;
      } else if (checks.synspoof?.level === "bad") {
        alertTone = "bad";
        head = "最要命的一条：跨包 TSval 时钟拆穿了无状态 SYN 改包";
        sub = checks.synspoof.summary;
      } else if (checks.split?.level === "bad") {
        alertTone = "bad";
        head = "最要命的一条：规则分流直接暴露了你的国内真实宽带";
        sub = checks.split.summary;
      } else if (checks.webrtc?.level === "bad") {
        alertTone = "bad";
        head = "最要命的一条：WebRTC 或 IPv6 穿透暴露了真实底层身份";
        sub = checks.webrtc.summary;
      } else if (checks.lease?.level === "bad") {
        alertTone = "bad";
        head = "最要命的一条：PeeringDB 流量画像拆穿了伪家宽机房";
        sub = checks.lease.summary;
      } else if (checks.reputation?.level === "bad") {
        alertTone = "bad";
        head = "高危出口污染：当前 IP 或所在 C 段命中实时黑名单/威胁库";
        sub = checks.reputation.summary;
      } else if (checks.fpb?.level === "bad") {
        alertTone = "bad";
        head = "最要命的一条：硬件与内核特征拆穿了指纹浏览器伪装";
        sub = checks.fpb.summary;
      } else if (R.cacheResurrected) {
        alertTone = "bad";
        head = "最要命的一条：你清掉了本地记录，网站还是靠浏览器缓存认出了你";
        sub = checks.fp?.summary || "已清空本地存储试图伪装新访客，但 HTTP ETag 缓存或残余存储仍暴露回访身份。";
      } else if (checks.tz?.level === "bad") {
        alertTone = "bad";
        head = "一眼识破的破绽：出口 IP 在海外，电脑时钟却还在原时区";
        sub = checks.tz.summary;
      } else if (checks.rtt?.level === "bad") {
        alertTone = "bad";
        head = "物理测距露馅：往返延迟远超直连光缆上限，暴露多跳代理中转";
        sub = checks.rtt.summary;
      } else if (checks.tamper?.level === "bad" || checks.tamper?.level === "warn") {
        alertTone = checks.tamper.level;
        head = "浏览器环境存在插件钩子或请求头不一致";
        sub = checks.tamper.summary;
      } else if (R.finished && (R.unverifiedCnt || 0) > 0) {
        alertTone = "warn";
        head = `部分网络情报探针响应超时（${R.unverifiedCnt} 项未核验）`;
        sub = "当前代理链路延迟较高或阻断了部分探测接口，可点击下方对应行的「重测」按钮单独补测。";
      }

      wowEl.className = "rounded-lg border p-3.5 text-xs leading-relaxed " + (
        alertTone === "bad" ? "border-red-200 bg-red-50/80 text-red-900 dark:bg-red-500/10 dark:border-red-500/25 dark:text-red-200"
          : alertTone === "warn" ? "border-amber-200 bg-amber-50/80 text-amber-900 dark:bg-amber-500/10 dark:border-amber-500/25 dark:text-amber-200"
          : "border-teal-200 bg-teal-50/70 text-teal-900 dark:bg-teal-500/10 dark:border-teal-500/25 dark:text-teal-200"
      );
      wowIcon.className = "mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full font-bold text-[11px] " + (
        alertTone === "bad" ? "bg-red-600 text-white" : alertTone === "warn" ? "bg-amber-500 text-white" : "bg-teal-600 text-white"
      );
      wowIcon.textContent = alertTone === "ok" ? "✓" : "!";
      wowTitle.textContent = head;
      wowDesc.textContent = sub;
    }

    // Build Natural Forensic Narrative Paragraphs
    const langStr = R.langs?.[0] ? `${languageName(R.langs[0])} (${R.langs[0]})` : "未知语言";
    const tzStr = R.tz ? `${tzGenericLabel(R.tz)} (${R.tz})` : "未知时区";
    const clockStr = R.h12 ? "12 小时制" : "24 小时制";

    // Hardware tier assessment
    const gStr = `${R.gpuDiscrete || ""} ${R.gpuClean || ""}`;
    const isHighRig = !!R.gpuDiscrete || /RTX\s?(30|40|50)\d0|RX\s?[79]\d{3}|Apple M\d+ (Pro|Max|Ultra)|Apple M[45]/i.test(gStr);
    const rigLabel = R.gpuSoft ? "虚拟机/软件渲染容器" : isHighRig && (R.hz || 60) >= 120 ? "高刷高性能工作站/游戏主机" : isHighRig ? "高算力主力生产力设备" : "日常主流办公终端";

    const p1 = `在打开网页的几百毫秒内，网站无需申请任何权限就已经拼出了你的画像：你大概率来自 ${chip(originText, ["langs", "tz", "ex_cn"], cnLeak || (origin?.cc && origin.cc !== R.ipCC) ? "warn" : "default", !!cnLeak)}，当前网络出口位于 ${chip(exitText, ["ip", "geo"], "default", true)}。你日常阅读 ${chip(langStr, ["langs"])}，系统时钟设在 ${chip(tzStr, ["tz", "tzoff"], checks.tz?.level === "bad" ? "bad" : "default")}，习惯使用 ${chip(clockStr, ["hour"])}。`;

    const p2 = `你手头这台设备运行着 ${chip(`${R.osLabel || "未知系统"} (${navigator.hardwareConcurrency || "?"} 核)`, ["os", "cpu", "arch"])}，浏览器是真正跑在 ${chip(`${R.engine || "?"} 内核上的 ${R.browserLabel || "浏览器"}`, ["browser", "engine", "engver"])}；显示器物理面板分辨率为 ${chip(`${R.physScreen || "–"} · ${R.hz || 60} Hz`, ["screen", "hz"])}，图形显卡为 ${chip(R.gpuDiscrete ? `${R.gpuDiscrete} + ${R.gpuClean}` : (R.gpuClean || "未知显卡"), ["gpu", "webgpu"], R.gpuSoft ? "bad" : "default")} —— 在风控模型里属于一台 ${chip(rigLabel, ["gpu", "screen", "cpu", "cpubench"])}。`;

    const netTypeDesc = R.netKind === "dc" ? `数据中心机房线路 (${R.org || R.asn})` : `原生宽带/ISP (${R.org || R.asn})`;
    const rttDesc = R.httpRtt != null && R.srvTcpRtt != null
      ? `浏览器往返 ${R.httpRtt}ms / 服务端握手 ${R.srvTcpRtt}ms`
      : "延迟已采样";
    const pur = R.intel?.purity;
    const purityPhrase = pur?.score != null
      ? `，多源综合信誉纯净度为 ${chip(`${pur.score}/100 (${pur.grade} 级)`, ["rep_score", "rep_votes", "rep_neigh"], pur.score >= 82 ? "ok" : pur.score >= 58 ? "warn" : "bad")}`
      : "";
    const p3 = `网络链路方面，你正通过 ${chip(netTypeDesc, ["isp", "nettype", "rep_asn"], R.netKind === "dc" ? "bad" : "ok", true)} 访问本站${purityPhrase}，递归 DNS 位于 ${chip(R.dnsCC ? `${flagEmoji(R.dnsCC)} ${countryName(R.dnsCC)}` : "未检出", ["dns", "ecs"], checks.dns?.level === "bad" ? "bad" : "default")}，物理握手测距显示 ${chip(rttDesc, ["tcprtt", "muxjitter"], checks.rtt?.level === "bad" ? "bad" : checks.rtt?.level === "warn" ? "warn" : "ok")}。`;

    const extCombined = Array.from(new Set([...(R.extWar || []), ...(R.domExts || []).map(x => x[1])]));
    const extPhrase = extCombined.length
      ? `并且被扫描出安装了 ${chip(extCombined.slice(0, 4).join("、"), ["extwar", "ext"], "warn")}`
      : `未暴露公开的扩展静态资源`;
    const adPhrase = R.adblock ? chip("已开启广告拦截", ["adblock"], "ok") : chip("未装广告拦截器", ["adblock"]);
    const trackPhrase = R.etag?.seen
      ? chip(`清 Cookie 也没用：HTTP ETag 缓存编号 ${R.etag.id.slice(0, 6)} 已认出你回访`, ["etag", "traces"], "warn")
      : chip(`跨浏览器物理硬件编号 ${R.hwId || "--"} 始终跟着这台设备`, ["hwid", "fpid"]);

    const roleStr = (R.fontRoles || []).length ? R.fontRoles.map(r => r[1]).join("、") : "标准系统默认字库（未透露特定职业软件）";
    const p4 = `使用习惯上，你偏好 ${chip(R.sysDark ? "深色外观" : "浅色外观", ["scheme"])}，${adPhrase}，${extPhrase}。防关联方面，${trackPhrase}；从已安装的 ${(R.fonts || []).length} 款代表性字体来看，你的软件环境偏向 ${chip(roleStr, ["fonts", "fontfp"])}。`;

    $("#storyProse").innerHTML = `<p>${p1}</p><p>${p2}</p><p>${p3}</p><p>${p4}</p>`;

    // Risk & Persona Labels
    const tags = [];
    if (checks.tz?.level === "bad" || checks.split?.level !== "ok" || checks.conn?.level === "bad" || checks.reality?.level === "bad" || R.netKind === "dc") {
      tags.push(["使用跨境代理", "bad"]);
    }
    if (checks.reality?.level === "bad") tags.push(["Reality 偷证书实锤", "bad"]);
    if (R.netKind === "dc") tags.push(["机房 IDC 出口", "bad"]);
    if (R.intel?.asnProfile?.inferred?.conflict) tags.push(["伪家宽自报冲突", "bad"]);
    if (R.intel?.consensus?.isNative === false) tags.push(["跨国广播 IP", "warn"]);
    if ((R.intel?.cidr?.neighbours?.dirtyCount || 0) > 0) tags.push([`C 段脏邻居 (${R.intel.cidr.neighbours.dirtyCount})`, "warn"]);
    if (R.exits?.ex_cn?.cc === "CN" && R.ipCC !== "CN") tags.push(["规则分流漏底", "bad"]);
    if (/^(macOS|iOS|iPadOS)/.test(R.dev?.os || "")) tags.push(["Apple 生态用户", "info"]);
    if (isHighRig) tags.push(["高配硬件终端", "info"]);
    if (R.multiScreen) tags.push(["多屏办公族", "info"]);
    for (const [k] of R.fontRoles || []) {
      if (k === "dev") tags.push(["技术/开发者", "info"]);
      if (k === "design") tags.push(["视觉/创意设计", "info"]);
    }
    if ((R.domExts || []).some(x => x[0] === "crypto") || (R.extWar || []).some(n => /MetaMask|Phantom|OKX|Rabby|Bitget/.test(n))) {
      tags.push(["Web3 / 加密钱包用户", "warn"]);
    }
    if ((R.extWar || []).some(n => /1Password|Bitwarden|LastPass/.test(n))) {
      tags.push(["密码管理器用户", "ok"]);
    }
    if (R.adblock) tags.push(["开启广告过滤", "ok"]);
    tags.push(["brave", "rfp", "fpp", "atfp"].includes(R.shieldKind) ? ["强防指纹护盾", "ok"] : ["原生裸奔指纹", "neutral"]);

    const tagCls = {
      bad: "bg-red-50 text-red-700 border-red-200 dark:bg-red-500/10 dark:text-red-400 dark:border-red-500/20",
      warn: "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-500/10 dark:text-amber-400 dark:border-amber-500/20",
      ok: "bg-teal-50 text-teal-700 border-teal-200 dark:bg-teal-500/10 dark:text-teal-400 dark:border-teal-500/20",
      info: "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-500/10 dark:text-blue-400 dark:border-blue-500/20",
      neutral: "bg-gray-100 text-gray-700 border-gray-200 dark:bg-neutral-800 dark:text-neutral-300 dark:border-neutral-700"
    };
    $("#personaTags").innerHTML = tags.map(([label, t]) =>
      `<span class="py-1 px-2.5 rounded-md text-xs font-medium border ${tagCls[t] || tagCls.neutral}">${esc(label)}</span>`
    ).join("");
  }

  /* ---------- Target Country / Region Alignment Simulator ---------- */
  function renderTargetSimulator() {
    const T = targetCountry || R.ipCC || "US";
    const tName = `${flagEmoji(T)} ${countryName(T)}`;

    // Sync pill active state
    $$("#targetQuickPills .tg-pill").forEach(btn => {
      const on = btn.dataset.tgcc === targetCountry;
      btn.className = "tg-pill py-1 px-2.5 rounded-lg text-xs font-medium border transition " + (
        on
          ? "border-blue-600 bg-blue-600 text-white shadow-2xs"
          : "border-gray-200 bg-white text-gray-700 hover:bg-gray-50 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-300"
      );
    });
    const sel = $("#targetSelect");
    if (sel && sel.value !== targetCountry) {
      sel.value = Array.from(sel.options).some(o => o.value === targetCountry) ? targetCountry : "";
    }

    const firstLang = (R.langs || [])[0] || "";
    const langMatch = firstLang ? (spokenIn(firstLang).includes(T) || langCC(firstLang) === T || (T !== "CN" && /^en\b/i.test(firstLang) && ["US", "GB", "SG", "HK", "CA", "AU"].includes(T))) : null;
    const tzMatch = R.tz ? tzCC(R.tz) === T : null;
    const ipMatch = R.ipCC ? R.ipCC === T : null;
    const ispClean = R.srv ? (R.netKind !== "dc" && R.intel?.consensus?.isNative !== false) : null;
    const dnsMatch = R.dnsCC ? R.dnsCC === T : null;
    const rtcClean = R.checks?.webrtc ? R.checks.webrtc.level === "ok" && !(R.exits?.ex_cn?.cc === "CN" && T !== "CN") : null;

    const cards = [
      ["出口 IP 归属地", ipMatch, ipMatch ? `已位于 ${countryName(T)}` : `当前在 ${countryName(R.ipCC)}，需切换 ${countryName(T)} 节点`],
      ["原生家宽属性", ispClean, ispClean ? "原生住宅/ISP 直配线路" : R.intel?.consensus?.isNative === false ? "当前为跨国广播 IP，建议换本土原生段" : "当前为机房 VPS，高风控建议换家宽 ISP"],
      ["系统时区对齐", tzMatch, tzMatch ? `${R.tz} 已对齐` : `当前为 ${R.tz || "?"}，需改为 ${countryName(T)} 时区`],
      ["浏览器首选语言", langMatch, langMatch ? `${firstLang} 符合当地习惯` : `当前首选 ${firstLang || "?"}，建议前置当地语种`],
      ["DNS 解析服务器", dnsMatch, dnsMatch == null ? "DNS 探针未返回" : dnsMatch ? `已由 ${countryName(T)} 解析` : `当前在 ${countryName(R.dnsCC)}，建议开远端代理解析`],
      ["分流与 UDP 密封", rtcClean, rtcClean ? "WebRTC 与分流未漏底" : "存在国内分流直连或 WebRTC 泄漏"]
    ];

    const failCnt = cards.filter(([, ok]) => ok === false).length;
    const vBadge = $("#targetVerdictBadge");
    if (vBadge) {
      vBadge.textContent = failCnt === 0 ? `伪装成 ${tName}：6 项全数达标` : `伪装成 ${tName}：差 ${failCnt} 项未对齐`;
      vBadge.className = "inline-flex items-center py-1 px-2.5 rounded-full text-xs font-medium " + (
        failCnt === 0 ? "bg-teal-50 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400"
          : "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400"
      );
    }

    const grid = $("#targetCardsGrid");
    if (grid) {
      grid.innerHTML = cards.map(([title, ok, desc]) => `
        <div class="rounded-lg border p-3 transition ${ok === true
          ? "border-teal-200/80 bg-teal-50/40 dark:bg-teal-500/10 dark:border-teal-500/20"
          : ok === false
          ? "border-red-200/80 bg-red-50/40 dark:bg-red-500/10 dark:border-red-500/20"
          : "border-gray-200 bg-gray-50 dark:bg-neutral-800 dark:border-neutral-700"}">
          <div class="flex items-center justify-between gap-1.5">
            <span class="text-xs font-semibold text-gray-900 dark:text-white">${esc(title)}</span>
            <span class="inline-flex size-4 items-center justify-center rounded-full text-[10px] font-bold ${ok === true ? "bg-teal-600 text-white" : ok === false ? "bg-red-600 text-white" : "bg-gray-300 text-gray-700"}">${ok === true ? "✓" : ok === false ? "✕" : "–"}</span>
          </div>
          <p class="mt-1.5 text-[11px] leading-snug text-gray-600 dark:text-neutral-300">${esc(desc)}</p>
        </div>
      `).join("");
    }
  }

  /* ---------- Search, Category Tabs, Tooltips & Toolbar Actions ---------- */
  function applyExplorerFilter() {
    const q = searchQuery.trim().toLowerCase();
    for (const [gid] of GROUPS) {
      const sec = $(`[data-gsec="${gid}"]`);
      if (!sec) continue;
      if (activeGroup !== "all" && activeGroup !== gid) {
        sec.hidden = true;
        continue;
      }
      const rows = $$("[data-probe]", sec);
      let vis = 0;
      for (const r of rows) {
        const pid = r.dataset.probe;
        const meta = SNIFFER_MAP[pid];
        const val = (R.values && R.values[pid]) || "";
        const match = !q || pid.toLowerCase().includes(q) || meta.title.toLowerCase().includes(q) || meta.desc.toLowerCase().includes(q) || val.toLowerCase().includes(q);
        r.hidden = !match;
        if (match) vis++;
      }
      sec.hidden = vis === 0;
    }
  }

  function highlightProbes(ids) {
    if (!ids.length) return;
    activeGroup = "all";
    searchQuery = "";
    const inp = $("#probeSearch");
    if (inp) inp.value = "";
    $$("#groupTabs .gtab-btn").forEach((b, i) => {
      b.className = "gtab-btn shrink-0 py-1.5 px-3 inline-flex items-center gap-1.5 rounded-lg text-xs font-medium transition " + (
        i === 0 ? "bg-blue-600 text-white shadow-2xs" : "bg-gray-100 text-gray-600 hover:bg-gray-200/70 dark:bg-neutral-800 dark:text-neutral-300"
      );
    });
    applyExplorerFilter();
    $$(".probe-lit").forEach(el => el.classList.remove("probe-lit"));
    const first = ROW_EL[ids[0]];
    if (first) first.scrollIntoView({ behavior: "smooth", block: "center" });
    ids.forEach(id => {
      const el = ROW_EL[id];
      if (el) {
        el.classList.add("probe-lit");
        setTimeout(() => el.classList.remove("probe-lit"), 2600);
      }
    });
  }

  function bindEvents() {
    // Arbitrary Public IP Reputation Inspector (#ipQueryForm / #extIpBanner)
    $("#ipQueryForm")?.addEventListener("submit", e => {
      e.preventDefault();
      inspectCustomIp($("#ipQueryInput")?.value || "");
    });
    $("#btnResetSelfIp")?.addEventListener("click", () => {
      const inp = $("#ipQueryInput");
      if (inp) inp.value = "";
      inspectCustomIp("");
    });
    $("#btnJumpRep")?.addEventListener("click", () => {
      activeGroup = "rep";
      searchQuery = "";
      const inp = $("#probeSearch");
      if (inp) inp.value = "";
      $$("#groupTabs .gtab-btn").forEach(b => {
        const on = b.dataset.gtab === "rep";
        b.setAttribute("aria-selected", on ? "true" : "false");
        b.className = "gtab-btn shrink-0 py-1.5 px-3 inline-flex items-center gap-1.5 rounded-lg text-xs font-medium transition " + (
          on ? "bg-blue-600 text-white shadow-2xs" : "bg-gray-100 text-gray-600 hover:bg-gray-200/70 dark:bg-neutral-800 dark:text-neutral-300"
        );
      });
      applyExplorerFilter();
      $("#explorerSection")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });

    // Theme switch
    $("#btnTheme")?.addEventListener("click", () => {
      const isDark = document.documentElement.classList.toggle("dark");
      store.set(SK.theme, isDark ? "dark" : "light");
    });

    // Privacy Mask toggle
    const applyMask = on => {
      document.body.classList.toggle("is-masked", on);
      const btn = $("#btnMask");
      if (btn) btn.setAttribute("aria-pressed", on ? "true" : "false");
      const lbl = $("#btnMaskText");
      if (lbl) lbl.textContent = on ? "已打码" : "隐私打码";
    };
    if (store.get(SK.mask) === "1") applyMask(true);
    $("#btnMask")?.addEventListener("click", () => {
      const next = !document.body.classList.contains("is-masked");
      store.set(SK.mask, next ? "1" : "0");
      applyMask(next);
    });

    // Scene switch (disguise vs privacy)
    const syncSceneUI = () => {
      $$("#sceneSwitch .scene-btn").forEach(btn => {
        const on = btn.dataset.scene === currentScene;
        btn.setAttribute("aria-selected", on ? "true" : "false");
        btn.className = "scene-btn py-1.5 px-3 inline-flex items-center gap-x-1.5 text-xs font-medium rounded-md transition " + (
          on
            ? "bg-white text-gray-900 shadow-2xs dark:bg-neutral-900 dark:text-white"
            : "text-gray-600 hover:text-gray-900 dark:text-neutral-400 dark:hover:text-neutral-200"
        );
      });
    };
    syncSceneUI();
    $("#sceneSwitch")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-scene]");
      if (!btn || btn.dataset.scene === currentScene) return;
      currentScene = btn.dataset.scene;
      store.set(SK.scene, currentScene);
      syncSceneUI();
      renderChecksAndScore(false);
    });

    // Check Filter Bar (All / Issues / Passed)
    $("#checkFilterBar")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-ckfilter]");
      if (!btn) return;
      checkFilter = btn.dataset.ckfilter;
      $$("#checkFilterBar .ckf-btn").forEach(b => {
        const on = b.dataset.ckfilter === checkFilter;
        b.className = "ckf-btn py-1 px-2.5 text-xs font-medium rounded-md transition " + (
          on ? "bg-white text-gray-900 shadow-2xs dark:bg-neutral-900 dark:text-white" : "text-gray-600 hover:text-gray-900 dark:text-neutral-400"
        );
      });
      renderChecksAndScore(false);
    });

    // Priority box jump to check & open drawer
    $("#priorityList")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-jumpck]");
      if (!btn) return;
      const row = CHECK_EL[btn.dataset.jumpck];
      if (!row) return;
      row.hidden = false;
      const dr = $(".ck-drawer", row);
      if (dr) dr.hidden = false;
      row.scrollIntoView({ behavior: "smooth", block: "center" });
    });

    // Check drawers & Single-Check Retest ("重测")
    const RETEST_RUNNERS = {
      tz: [probeLocale],
      lang: [probeLocale],
      syslang: [probeFonts, probeVoices, probeKeyboard],
      dns: [probeDns],
      split: [probeServer, probeQuicAndExits],
      conn: [probeServer],
      synspoof: [probeServer, probeLatency],
      reality: [probeIntel],
      rtt: [probeServer, probeLatency, probeWebrtc],
      webrtc: [probeWebrtc, probeV6Mac],
      dc: [probeServer, probeIntel],
      lease: [probeIntel],
      reputation: [probeIntel],
      subpixel: [probeDeviceAndSpecs, probeSubpixelAndEngine],
      hwvirt: [probeGraphics, probeAsyncHardware, probeSubpixelAndEngine]
    };

    const onCheckContainerClick = async e => {
      const howBtn = e.target.closest("[data-howto]");
      if (howBtn) {
        const row = CHECK_EL[howBtn.dataset.howto];
        const dr = row && $(".ck-drawer", row);
        if (dr) dr.hidden = !dr.hidden;
        return;
      }
      const reBtn = e.target.closest("[data-retest]");
      if (reBtn) {
        const id = reBtn.dataset.retest;
        const fns = RETEST_RUNNERS[id] || [];
        if (!fns.length) return;
        reBtn.disabled = true;
        reBtn.textContent = "重测中…";
        for (const fn of fns) { try { await fn(); } catch (err) {} }
        renderChecksAndScore(false);
        renderPortrait();
        renderTargetSimulator();
        reBtn.disabled = false;
        reBtn.textContent = "重测";
        showToast(`已重测「${CORE_CHECKS.find(c => c[0] === id)?.[1] || id}」`);
      }
    };
    $("#coreChecksList")?.addEventListener("click", onCheckContainerClick);
    $("#protoChecksList")?.addEventListener("click", onCheckContainerClick);

    // Portrait chips -> jump & highlight source probes
    $("#storyProse")?.addEventListener("click", e => {
      const chipEl = e.target.closest("[data-from]");
      if (!chipEl) return;
      const ids = (chipEl.dataset.from || "").split(",").filter(Boolean);
      highlightProbes(ids);
    });

    // Target Country Pills & Select
    $("#targetQuickPills")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-tgcc]");
      if (!btn) return;
      targetCountry = btn.dataset.tgcc;
      store.set(SK.target, targetCountry);
      renderTargetSimulator();
    });
    $("#targetSelect")?.addEventListener("change", e => {
      targetCountry = e.target.value;
      store.set(SK.target, targetCountry);
      renderTargetSimulator();
    });

    // Explorer Category Tabs & Search
    $("#groupTabs")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-gtab]");
      if (!btn) return;
      activeGroup = btn.dataset.gtab;
      $$("#groupTabs .gtab-btn").forEach(b => {
        const on = b.dataset.gtab === activeGroup;
        b.setAttribute("aria-selected", on ? "true" : "false");
        b.className = "gtab-btn shrink-0 py-1.5 px-3 inline-flex items-center gap-1.5 rounded-lg text-xs font-medium transition " + (
          on ? "bg-blue-600 text-white shadow-2xs" : "bg-gray-100 text-gray-600 hover:bg-gray-200/70 dark:bg-neutral-800 dark:text-neutral-300"
        );
      });
      applyExplorerFilter();
    });

    $("#probeSearch")?.addEventListener("input", e => {
      searchQuery = e.target.value || "";
      applyExplorerFilter();
    });

    // Explorer Row Click to Copy & Tooltip Hover
    const tip = $("#globalTip");
    const showTip = (anchor, text) => {
      if (!tip || !text) return;
      tip.textContent = text;
      tip.hidden = false;
      const r = anchor.getBoundingClientRect();
      const top = Math.min(window.innerHeight - tip.offsetHeight - 12, Math.max(12, r.bottom + 8));
      const left = Math.min(window.innerWidth - tip.offsetWidth - 12, Math.max(12, r.left - 8));
      tip.style.top = `${top}px`;
      tip.style.left = `${left}px`;
    };
    const hideTip = () => { if (tip) tip.hidden = true; };

    $("#snifferContainer")?.addEventListener("mouseover", e => {
      const btn = e.target.closest("[data-tipbtn]");
      if (!btn) return;
      const row = ROW_EL[btn.dataset.tipbtn];
      if (row?.dataset.why) showTip(btn, row.dataset.why);
    });
    $("#snifferContainer")?.addEventListener("mouseout", e => {
      if (e.target.closest("[data-tipbtn]")) hideTip();
    });
    $("#snifferContainer")?.addEventListener("click", e => {
      if (e.target.closest("button:not([data-tipbtn])")) return;
      const tipBtn = e.target.closest("[data-tipbtn]");
      if (tipBtn) {
        const row = ROW_EL[tipBtn.dataset.tipbtn];
        if (row?.dataset.why) showTip(tipBtn, row.dataset.why);
        return;
      }
      const row = e.target.closest("[data-probe]");
      if (!row) return;
      const pid = row.dataset.probe;
      const meta = SNIFFER_MAP[pid];
      const val = (R.values && R.values[pid]) || $(".probe-val", row)?.textContent || "";
      copyText(`${meta?.title || pid}: ${val}`, `已复制「${meta?.title || pid}」`);
    });
    window.addEventListener("scroll", hideTip, { passive: true });

    // Forget stored traces button
    $("#btnForget")?.addEventListener("click", async () => {
      store.del(SK.traceTag);
      try { if (/^wp:/.test(window.name)) window.name = ""; } catch (e) {}
      try { indexedDB.deleteDatabase("whoprobe_store"); } catch (e) {}
      try { await caches.delete("whoprobe_cache"); } catch (e) {}
      showToast("已清除本站写入的 4 项浏览器存储测试留痕");
      await probeTraces();
    });

    // Copy Markdown/Text Report & Copy JSON
    $("#btnCopyTxt")?.addEventListener("click", () => {
      const masked = document.body.classList.contains("is-masked");
      const pur = R.intel?.purity;
      const lines = [
        `【WhoProbe v6.0 · 148项全栈指纹与出口信誉体检报告】`,
        `伪装健康度: ${R.score ?? "--"}/100 (等级 ${R.grade || "-"}) · 暴露破绽: ${R.totalIssues ?? 0} 处`,
        `出口纯净度: ${pur ? `${pur.score}/100 (${pur.grade} 级)` : "--"} · 脏邻居: ${R.intel?.cidr?.neighbours?.dirtyCount ?? 0} 个`,
        `推断设备: ${R.osLabel || "-"} · ${R.browserLabel || "-"} · 屏幕 ${R.physScreen || "-"} @ ${R.hz || 60}Hz`,
        `显卡渲染: ${R.gpuDiscrete ? R.gpuDiscrete + " + " + R.gpuClean : (R.gpuClean || "-")}`,
        `网络出口: ${masked ? "[已隐藏]" : (R.ip || "-")} (${countryName(R.ipCC)} · ${masked ? "[运营商已隐藏]" : (R.org || "-")})`,
        `三维测距: 浏览器 HTTP ${R.httpRtt ?? "-"}ms / 服务端 TCP 握手 ${R.srvTcpRtt ?? "-"}ms / STUN UDP ${R.stunRttMs ?? "-"}ms`,
        `跨站指纹: ${R.fpId || "-"} · 物理硬件码: ${R.hwId || "-"}`,
        ``,
        `[异常与风险项]`
      ];
      for (const [id, title] of CORE_CHECKS) {
        const c = R.checks?.[id];
        if (c && (c.level === "bad" || c.level === "warn")) {
          lines.push(`- [${c.level === "bad" ? "高危" : "可疑"}] ${title}: ${c.summary}`);
        }
      }
      copyText(lines.join("\n"), "已复制完整体检文字报告");
    });

    $("#btnCopyJson")?.addEventListener("click", () => {
      const masked = document.body.classList.contains("is-masked");
      const payload = {
        version: "6.0.1",
        timestamp: new Date().toISOString(),
        score: R.score,
        grade: R.grade,
        issues: R.totalIssues,
        purity: R.intel?.purity || null,
        scenarios: R.scenarios || null,
        inspectedIp: masked ? null : (R.extIntel?.targetIp || null),
        exit: masked ? { country: R.ipCC, netKind: R.netKind } : { ip: R.ip, country: R.ipCC, asn: R.asn, org: R.org, netKind: R.netKind },
        rtt: { browserHttpMs: R.httpRtt, serverTcpHandshakeMs: R.srvTcpRtt, stunUdpMs: R.stunRttMs, muxBurst: R.muxBurst || null },
        packet: R.srv?.packet || null,
        tls443: R.intel?.tls443 || null,
        ids: { fingerprintId: R.fpId, hardwareId: R.hwId },
        checks: R.checks,
        probes: masked
          ? Object.fromEntries(Object.entries(R.values || {}).map(([k, v]) => [k, SNIFFER_MAP[k]?.mask ? "[MASKED]" : v]))
          : R.values
      };
      copyText(JSON.stringify(payload, null, 2), "已复制 148 项完整 JSON 数据");
    });

    $("#btnCopyUrl")?.addEventListener("click", () => copyText(location.href, "已复制页面链接"));

    // Rerun all 148 probes
    $("#btnRerun")?.addEventListener("click", () => runAll());
  }

  /* ---------- Master Orchestrator ---------- */
  async function runAll() {
    const seq = ++runSeq;
    R = { t0: performance.now(), values: {}, finished: false };
    completedSet = new Set();

    const rerunBtn = $("#btnRerun"), rerunTxt = $("#btnRerunText");
    if (rerunBtn) rerunBtn.disabled = true;
    if (rerunTxt) rerunTxt.textContent = "检测中…";
    const dot = $("#liveDot");
    if (dot) dot.className = "size-1.5 rounded-full bg-blue-600 animate-pulse";

    // Reset rows visually
    for (const [id] of SNIFFERS) {
      const el = ROW_EL[id];
      if (el) {
        const v = $(".probe-val", el);
        if (v) { v.textContent = "检测中…"; v.className = `probe-val ${SNIFFER_MAP[id]?.mask ? "maskable " : ""}font-mono text-xs text-right text-gray-400 dark:text-neutral-500 truncate min-w-0 flex-1`; }
      }
    }
    updateProgress();

    // Phase 1: Synchronous & Instant Local Probes (< 30ms)
    probeLocale();
    probeDeviceAndSpecs();
    probeNavAndPrefs();
    probeLiesAndIframe();
    initInteractiveProbes();

    // Phase 2: Fonts, Graphics, Canvas & High-Entropy Hints (needed for composite IDs & portrait)
    await Promise.all([
      probeFonts(),
      probeGraphics(),
      probeCanvas(),
      probeSubpixelAndEngine()
    ]);
    await probeHighEntropyHints();

    // Render early partial portrait & checks while network probes finish
    if (seq !== runSeq) return;
    renderChecksAndScore(false);
    renderPortrait();
    renderTargetSimulator();

    // Phase 3: 全并行启动服务端抓包、多源出口情报、分流矩阵与异步硬件探针（消除高延迟住宅代理串行等待！）
    // 先发出首包 /api/who/me 以优先捕获干净 TCP SYN，80ms 后立即并发启动全部探针；一旦关键链路返回即渐进刷新 UI
    const pSrv = probeServer().then(() => {
      if (seq === runSeq) {
        renderChecksAndScore(false);
        renderPortrait();
        renderTargetSimulator();
      }
    });
    await new Promise(r => setTimeout(r, 80));
    if (seq !== runSeq) return;

    const pIntel = probeIntel().then(() => {
      if (seq === runSeq) {
        renderChecksAndScore(false);
        renderPortrait();
        renderTargetSimulator();
      }
    });
    const pExits = probeQuicAndExits().then(() => {
      if (seq === runSeq) {
        renderChecksAndScore(false);
        renderPortrait();
        renderTargetSimulator();
      }
    });
    // 等待 pSrv 完成或最多 1.2s 后启动延迟与微脉冲探测，既保证 R.srvTcpRtt 就绪，又绝不被慢连接卡死
    const pLat = Promise.race([pSrv, new Promise(r => setTimeout(r, 1200))]).then(() => probeLatency());

    await Promise.all([
      pSrv,
      pIntel,
      pLat,
      pExits,
      probeDns(),
      probeWebrtc(),
      probeAudioStack(),
      probeRefreshRate(),
      probeKeyboard(),
      probeVoices(),
      probeAsyncHardware(),
      probePermissions(),
      probeAdblock(),
      probeChromeExtWar(),
      probeWorkerRealm(),
      probeEtag(),
      probeTraces(),
      probeDomExtensions()
    ]);

    if (seq !== runSeq) return;

    // Phase 4: Derived Cross-Source Probes (IPv6 MAC, Shield Attribution, Composite Hardware/FP IDs)
    probeV6Mac();
    probeShield();
    await probeCompositeIds();

    R.finished = true;
    const elapsedSec = ((performance.now() - R.t0) / 1000).toFixed(1);

    renderChecksAndScore(true);
    renderPortrait();
    renderTargetSimulator();

    // Finalize navbar & progress state
    const bar = $("#topProgBar");
    if (bar) bar.style.width = "100%";
    const stTxt = $("#liveStatusText");
    if (stTxt) stTxt.textContent = `已完成 ${completedSet.size} / ${SNIFFERS.length} 项检测 · 耗时 ${elapsedSec}s`;
    if (dot) dot.className = "size-1.5 rounded-full bg-teal-500";
    const elap = $("#portraitElapsed");
    if (elap) elap.textContent = `148 项全量扫描 ${elapsedSec}s · 点击词条可定位原始探针`;
    if (rerunBtn) rerunBtn.disabled = false;
    if (rerunTxt) rerunTxt.textContent = "重新检测";

    if (window.HSStaticMethods?.autoInit) {
      try { window.HSStaticMethods.autoInit(); } catch (e) {}
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    buildInitialDOM();
    bindEvents();
    runAll();
  });
})();
