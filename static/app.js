/* WhoProbe v7.7.1 — 191-Probe L3–L7 Forensic, QUIC Initial JA4Q, Active :443 Reality & BGP Egress Intelligence Engine */
(function () {
  "use strict";

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
  const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const within = (p, ms, fb = null) => Promise.race([Promise.resolve(p).catch(() => fb), new Promise(r => setTimeout(() => r(fb), ms))]);
  const mq = q => { try { return window.matchMedia(q).matches; } catch (e) { return false; } };

  function siblingIpHref(host) {
    const h = String(host || "").trim().toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
    return /^who\.[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h) && !/^who\.(\d+\.){3}\d+$/.test(h)
      ? `https://ip.${h.slice(4)}/`
      : "";
  }
  const derivedIpHref = siblingIpHref(location.hostname);
  if (derivedIpHref) {
    const myIpTab = $("#myIpTab"), siblingNav = $("#siblingNav"), plainBrand = $("#brandPlainTitle");
    if (myIpTab && siblingNav) {
      myIpTab.href = derivedIpHref;
      siblingNav.hidden = false;
      if (plainBrand) plainBrand.hidden = true;
    }
  }

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

  /* ---------- Passive input-event trust recorder (armed at script load, summarized at the end of each scan) ---------- */
  const INPUT_LOG = { moves: 0, untrusted: 0, keys: 0, clicks: 0, touches: 0, wheels: 0, zeroMove: 0, cdpCoord: 0, ptrEvents: 0, pts: [], wheelDeltas: [], dwells: [], downAt: new Map() };
  function resetInputLog() {
    Object.assign(INPUT_LOG, { moves: 0, untrusted: 0, keys: 0, clicks: 0, touches: 0, wheels: 0, zeroMove: 0, cdpCoord: 0, ptrEvents: 0, pts: [], wheelDeltas: [], dwells: [], downAt: new Map() });
  }
  (function armInputRecorder() {
    const opt = { capture: true, passive: true };
    const rec = e => {
      if (e.isTrusted === false) INPUT_LOG.untrusted++;
      // brotector：CDP Input.dispatchMouseEvent 生成的事件 screenX/Y 恰等于 pageX/Y（窗口偏移为 0）；全屏与键盘触发（坐标全 0）豁免
      if ((e.type === "mousemove" || e.type === "mousedown") && (e.screenX || e.screenY)) {
        INPUT_LOG.ptrEvents++;
        if (e.screenX === e.pageX && e.screenY === e.pageY && window.outerHeight - window.innerHeight > 1) INPUT_LOG.cdpCoord++;
      }
      const now = performance.now();
      switch (e.type) {
        case "mousemove": {
          INPUT_LOG.moves++;
          const last = INPUT_LOG.pts[INPUT_LOG.pts.length - 1];
          if (last && (last.x !== e.clientX || last.y !== e.clientY) && e.movementX === 0 && e.movementY === 0) INPUT_LOG.zeroMove++;
          if (INPUT_LOG.pts.length < 800) INPUT_LOG.pts.push({ x: e.clientX, y: e.clientY, t: now });
          break;
        }
        case "keydown":
          INPUT_LOG.keys++;
          if (!e.repeat && INPUT_LOG.downAt.size < 32) INPUT_LOG.downAt.set(e.code || e.key || "_", now);
          break;
        case "keyup": {
          const k = e.code || e.key || "_";
          const t0 = INPUT_LOG.downAt.get(k);
          if (t0 != null) {
            INPUT_LOG.downAt.delete(k);
            if (INPUT_LOG.dwells.length < 120) INPUT_LOG.dwells.push(Math.max(0, now - t0));
          }
          break;
        }
        case "mousedown": INPUT_LOG.clicks++; break;
        case "touchstart": INPUT_LOG.touches++; break;
        case "wheel":
          INPUT_LOG.wheels++;
          if (INPUT_LOG.wheelDeltas.length < 120) INPUT_LOG.wheelDeltas.push({ dy: Math.abs(e.deltaY || 0), mode: e.deltaMode || 0 });
          break;
      }
    };
    try { ["mousemove", "keydown", "keyup", "mousedown", "touchstart", "wheel"].forEach(t => window.addEventListener(t, rec, opt)); } catch (e) {}
  })();

  /* ---------- Complete IANA Timezone -> ISO Country Map ---------- */
  const TZ_CC = {"Africa/Abidjan":"CI","Africa/Accra":"GH","Africa/Addis_Ababa":"ET","Africa/Algiers":"DZ","Africa/Asmara":"ER","Africa/Asmera":"ER","Africa/Bamako":"ML","Africa/Bangui":"CF","Africa/Banjul":"GM","Africa/Bissau":"GW","Africa/Blantyre":"MW","Africa/Brazzaville":"CG","Africa/Bujumbura":"BI","Africa/Cairo":"EG","Africa/Casablanca":"MA","Africa/Ceuta":"ES","Africa/Conakry":"GN","Africa/Dakar":"SN","Africa/Dar_es_Salaam":"TZ","Africa/Djibouti":"DJ","Africa/Douala":"CM","Africa/El_Aaiun":"EH","Africa/Freetown":"SL","Africa/Gaborone":"BW","Africa/Harare":"ZW","Africa/Johannesburg":"ZA","Africa/Juba":"SS","Africa/Kampala":"UG","Africa/Khartoum":"SD","Africa/Kigali":"RW","Africa/Kinshasa":"CD","Africa/Lagos":"NG","Africa/Libreville":"GA","Africa/Lome":"TG","Africa/Luanda":"AO","Africa/Lubumbashi":"CD","Africa/Lusaka":"ZM","Africa/Malabo":"GQ","Africa/Maputo":"MZ","Africa/Maseru":"LS","Africa/Mbabane":"SZ","Africa/Mogadishu":"SO","Africa/Monrovia":"LR","Africa/Nairobi":"KE","Africa/Ndjamena":"TD","Africa/Niamey":"NE","Africa/Nouakchott":"MR","Africa/Ouagadougou":"BF","Africa/Porto-Novo":"BJ","Africa/Sao_Tome":"ST","Africa/Tripoli":"LY","Africa/Tunis":"TN","Africa/Windhoek":"NA","America/Adak":"US","America/Anchorage":"US","America/Anguilla":"AI","America/Antigua":"AG","America/Araguaina":"BR","America/Argentina/Buenos_Aires":"AR","America/Argentina/Catamarca":"AR","America/Argentina/Cordoba":"AR","America/Argentina/Jujuy":"AR","America/Argentina/La_Rioja":"AR","America/Argentina/Mendoza":"AR","America/Argentina/Rio_Gallegos":"AR","America/Argentina/Salta":"AR","America/Argentina/San_Juan":"AR","America/Argentina/San_Luis":"AR","America/Argentina/Tucuman":"AR","America/Argentina/Ushuaia":"AR","America/Aruba":"AW","America/Asuncion":"PY","America/Atikokan":"CA","America/Bahia":"BR","America/Bahia_Banderas":"MX","America/Barbados":"BB","America/Belem":"BR","America/Belize":"BZ","America/Blanc-Sablon":"CA","America/Boa_Vista":"BR","America/Bogota":"CO","America/Boise":"US","America/Buenos_Aires":"AR","America/Cambridge_Bay":"CA","America/Campo_Grande":"BR","America/Cancun":"MX","America/Caracas":"VE","America/Catamarca":"AR","America/Cayenne":"GF","America/Cayman":"KY","America/Chicago":"US","America/Chihuahua":"MX","America/Ciudad_Juarez":"MX","America/Coral_Harbour":"CA","America/Cordoba":"AR","America/Costa_Rica":"CR","America/Coyhaique":"CL","America/Creston":"CA","America/Cuiaba":"BR","America/Curacao":"CW","America/Danmarkshavn":"GL","America/Dawson":"CA","America/Dawson_Creek":"CA","America/Denver":"US","America/Detroit":"US","America/Dominica":"DM","America/Edmonton":"CA","America/Eirunepe":"BR","America/El_Salvador":"SV","America/Fort_Nelson":"CA","America/Fortaleza":"BR","America/Glace_Bay":"CA","America/Godthab":"GL","America/Goose_Bay":"CA","America/Grand_Turk":"TC","America/Grenada":"GD","America/Guadeloupe":"GP","America/Guatemala":"GT","America/Guayaquil":"EC","America/Guyana":"GY","America/Halifax":"CA","America/Havana":"CU","America/Hermosillo":"MX","America/Indiana/Indianapolis":"US","America/Indiana/Knox":"US","America/Indiana/Marengo":"US","America/Indiana/Petersburg":"US","America/Indiana/Tell_City":"US","America/Indiana/Vevay":"US","America/Indiana/Vincennes":"US","America/Indiana/Winamac":"US","America/Indianapolis":"US","America/Inuvik":"CA","America/Iqaluit":"CA","America/Jamaica":"JM","America/Jujuy":"AR","America/Juneau":"US","America/Kentucky/Louisville":"US","America/Kentucky/Monticello":"US","America/Kralendijk":"BQ","America/La_Paz":"BO","America/Lima":"PE","America/Los_Angeles":"US","America/Louisville":"US","America/Lower_Princes":"SX","America/Maceio":"BR","America/Managua":"NI","America/Manaus":"BR","America/Marigot":"MF","America/Martinique":"MQ","America/Matamoros":"MX","America/Mazatlan":"MX","America/Mendoza":"AR","America/Menominee":"US","America/Merida":"MX","America/Metlakatla":"US","America/Mexico_City":"MX","America/Miquelon":"PM","America/Moncton":"CA","America/Monterrey":"MX","America/Montevideo":"UY","America/Montreal":"CA","America/Montserrat":"MS","America/Nassau":"BS","America/New_York":"US","America/Nome":"US","America/Noronha":"BR","America/North_Dakota/Beulah":"US","America/North_Dakota/Center":"US","America/North_Dakota/New_Salem":"US","America/Nuuk":"GL","America/Ojinaga":"MX","America/Panama":"PA","America/Paramaribo":"SR","America/Phoenix":"US","America/Port_of_Spain":"TT","America/Port-au-Prince":"HT","America/Porto_Velho":"BR","America/Puerto_Rico":"PR","America/Punta_Arenas":"CL","America/Rankin_Inlet":"CA","America/Recife":"BR","America/Regina":"CA","America/Resolute":"CA","America/Rio_Branco":"BR","America/Santarem":"BR","America/Santiago":"CL","America/Santo_Domingo":"DO","America/Sao_Paulo":"BR","America/Scoresbysund":"GL","America/Sitka":"US","America/St_Barthelemy":"BL","America/St_Johns":"CA","America/St_Kitts":"KN","America/St_Lucia":"LC","America/St_Thomas":"VI","America/St_Vincent":"VC","America/Swift_Current":"CA","America/Tegucigalpa":"HN","America/Thule":"GL","America/Tijuana":"MX","America/Toronto":"CA","America/Tortola":"VG","America/Vancouver":"CA","America/Whitehorse":"CA","America/Winnipeg":"CA","America/Yakutat":"US","Antarctica/Casey":"AQ","Antarctica/Davis":"AQ","Antarctica/DumontDUrville":"AQ","Antarctica/Macquarie":"AU","Antarctica/Mawson":"AQ","Antarctica/McMurdo":"AQ","Antarctica/Palmer":"AQ","Antarctica/Rothera":"AQ","Antarctica/Syowa":"AQ","Antarctica/Troll":"AQ","Antarctica/Vostok":"AQ","Arctic/Longyearbyen":"SJ","Asia/Aden":"YE","Asia/Almaty":"KZ","Asia/Amman":"JO","Asia/Anadyr":"RU","Asia/Aqtau":"KZ","Asia/Aqtobe":"KZ","Asia/Ashgabat":"TM","Asia/Atyrau":"KZ","Asia/Baghdad":"IQ","Asia/Bahrain":"BH","Asia/Baku":"AZ","Asia/Bangkok":"TH","Asia/Barnaul":"RU","Asia/Beirut":"LB","Asia/Bishkek":"KG","Asia/Brunei":"BN","Asia/Calcutta":"IN","Asia/Chita":"RU","Asia/Chongqing":"CN","Asia/Colombo":"LK","Asia/Damascus":"SY","Asia/Dhaka":"BD","Asia/Dili":"TL","Asia/Dubai":"AE","Asia/Dushanbe":"TJ","Asia/Famagusta":"CY","Asia/Gaza":"PS","Asia/Harbin":"CN","Asia/Hebron":"PS","Asia/Ho_Chi_Minh":"VN","Asia/Hong_Kong":"HK","Asia/Hovd":"MN","Asia/Irkutsk":"RU","Asia/Istanbul":"TR","Asia/Jakarta":"ID","Asia/Jayapura":"ID","Asia/Jerusalem":"IL","Asia/Kabul":"AF","Asia/Kamchatka":"RU","Asia/Karachi":"PK","Asia/Kashgar":"CN","Asia/Kathmandu":"NP","Asia/Katmandu":"NP","Asia/Khandyga":"RU","Asia/Kolkata":"IN","Asia/Krasnoyarsk":"RU","Asia/Kuala_Lumpur":"MY","Asia/Kuching":"MY","Asia/Kuwait":"KW","Asia/Macao":"MO","Asia/Macau":"MO","Asia/Magadan":"RU","Asia/Makassar":"ID","Asia/Manila":"PH","Asia/Muscat":"OM","Asia/Nicosia":"CY","Asia/Novokuznetsk":"RU","Asia/Novosibirsk":"RU","Asia/Omsk":"RU","Asia/Oral":"KZ","Asia/Phnom_Penh":"KH","Asia/Pontianak":"ID","Asia/Pyongyang":"KP","Asia/Qatar":"QA","Asia/Qostanay":"KZ","Asia/Qyzylorda":"KZ","Asia/Rangoon":"MM","Asia/Riyadh":"SA","Asia/Saigon":"VN","Asia/Sakhalin":"RU","Asia/Samarkand":"UZ","Asia/Seoul":"KR","Asia/Shanghai":"CN","Asia/Singapore":"SG","Asia/Srednekolymsk":"RU","Asia/Taipei":"TW","Asia/Tashkent":"UZ","Asia/Tbilisi":"GE","Asia/Tehran":"IR","Asia/Tel_Aviv":"IL","Asia/Thimphu":"BT","Asia/Tokyo":"JP","Asia/Tomsk":"RU","Asia/Ulaanbaatar":"MN","Asia/Urumqi":"CN","Asia/Ust-Nera":"RU","Asia/Vientiane":"LA","Asia/Vladivostok":"RU","Asia/Yakutsk":"RU","Asia/Yangon":"MM","Asia/Yekaterinburg":"RU","Asia/Yerevan":"AM","Atlantic/Azores":"PT","Atlantic/Bermuda":"BM","Atlantic/Canary":"ES","Atlantic/Cape_Verde":"CV","Atlantic/Faeroe":"FO","Atlantic/Faroe":"FO","Atlantic/Madeira":"PT","Atlantic/Reykjavik":"IS","Atlantic/South_Georgia":"GS","Atlantic/St_Helena":"SH","Atlantic/Stanley":"FK","Australia/Adelaide":"AU","Australia/Brisbane":"AU","Australia/Broken_Hill":"AU","Australia/Darwin":"AU","Australia/Eucla":"AU","Australia/Hobart":"AU","Australia/Lindeman":"AU","Australia/Lord_Howe":"AU","Australia/Melbourne":"AU","Australia/Perth":"AU","Australia/Sydney":"AU","Europe/Amsterdam":"NL","Europe/Andorra":"AD","Europe/Astrakhan":"RU","Europe/Athens":"GR","Europe/Belgrade":"RS","Europe/Berlin":"DE","Europe/Bratislava":"SK","Europe/Brussels":"BE","Europe/Bucharest":"RO","Europe/Budapest":"HU","Europe/Busingen":"DE","Europe/Chisinau":"MD","Europe/Copenhagen":"DK","Europe/Dublin":"IE","Europe/Gibraltar":"GI","Europe/Guernsey":"GG","Europe/Helsinki":"FI","Europe/Isle_of_Man":"IM","Europe/Istanbul":"TR","Europe/Jersey":"JE","Europe/Kaliningrad":"RU","Europe/Kiev":"UA","Europe/Kirov":"RU","Europe/Kyiv":"UA","Europe/Lisbon":"PT","Europe/Ljubljana":"SI","Europe/London":"GB","Europe/Luxembourg":"LU","Europe/Madrid":"ES","Europe/Malta":"MT","Europe/Mariehamn":"AX","Europe/Minsk":"BY","Europe/Monaco":"MC","Europe/Moscow":"RU","Europe/Oslo":"NO","Europe/Paris":"FR","Europe/Podgorica":"ME","Europe/Prague":"CZ","Europe/Riga":"LV","Europe/Rome":"IT","Europe/Samara":"RU","Europe/San_Marino":"SM","Europe/Sarajevo":"BA","Europe/Saratov":"RU","Europe/Simferopol":"UA","Europe/Skopje":"MK","Europe/Sofia":"BG","Europe/Stockholm":"SE","Europe/Tallinn":"EE","Europe/Tirane":"AL","Europe/Ulyanovsk":"RU","Europe/Vaduz":"LI","Europe/Vatican":"VA","Europe/Vienna":"AT","Europe/Vilnius":"LT","Europe/Volgograd":"RU","Europe/Warsaw":"PL","Europe/Zagreb":"HR","Europe/Zurich":"CH","Hongkong":"HK","Indian/Antananarivo":"MG","Indian/Chagos":"IO","Indian/Christmas":"CX","Indian/Cocos":"CC","Indian/Comoro":"KM","Indian/Kerguelen":"TF","Indian/Mahe":"SC","Indian/Maldives":"MV","Indian/Mauritius":"MU","Indian/Mayotte":"YT","Indian/Reunion":"RE","Japan":"JP","Pacific/Apia":"WS","Pacific/Auckland":"NZ","Pacific/Bougainville":"PG","Pacific/Chatham":"NZ","Pacific/Chuuk":"FM","Pacific/Easter":"CL","Pacific/Efate":"VU","Pacific/Enderbury":"KI","Pacific/Fakaofo":"TK","Pacific/Fiji":"FJ","Pacific/Funafuti":"TV","Pacific/Galapagos":"EC","Pacific/Gambier":"PF","Pacific/Guadalcanal":"SB","Pacific/Guam":"GU","Pacific/Honolulu":"US","Pacific/Kanton":"KI","Pacific/Kiritimati":"KI","Pacific/Kosrae":"FM","Pacific/Kwajalein":"MH","Pacific/Majuro":"MH","Pacific/Marquesas":"PF","Pacific/Midway":"UM","Pacific/Nauru":"NR","Pacific/Niue":"NU","Pacific/Norfolk":"NF","Pacific/Noumea":"NC","Pacific/Pago_Pago":"AS","Pacific/Palau":"PW","Pacific/Pitcairn":"PN","Pacific/Pohnpei":"FM","Pacific/Ponape":"FM","Pacific/Port_Moresby":"PG","Pacific/Rarotonga":"CK","Pacific/Saipan":"MP","Pacific/Tahiti":"PF","Pacific/Tarawa":"KI","Pacific/Tongatapu":"TO","Pacific/Truk":"FM","Pacific/Wake":"UM","Pacific/Wallis":"WF","PRC":"CN","ROC":"TW","ROK":"KR","Singapore":"SG","US/Central":"US","US/Eastern":"US","US/Mountain":"US","US/Pacific":"US"};

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

  /* ---------- 8 Groups & 191 Genuine Probes Catalog ---------- */
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

  // [id, group, title, maskSensitive, whyDesc] — Exactly 191 probes
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
    ["wsping", "net", "服务端主动控制帧 Ping 测距", false, "服务端在 WebSocket 通道主动连发 RFC 6455 Ping 控制帧，测量浏览器底层 C++ 网络进程自动回传 Pong 的纯传输耗时（绕过页面 JS 主线程节流），与 HTTP fetch 及 TCP 握手交叉核验。"],
    ["muxjitter", "net", "微脉冲粘包与多路复用抖动", false, "连续发射微间隔并发 HTTP 脉冲，对比服务端微秒级到达间隔压缩比与 RTT 抖动标准差，识别 smux/yamux/h2mux 隧道合并特征。"],
    ["clock", "net", "本机时钟与服务端偏差", false, "利用往返中点校准法测量浏览器系统时间与服务端标准时间的快慢误差。"],
    ["proto", "net", "HTTP 与 TLS 协商套件", false, "当前页面连接实际协商的 HTTP 版本、TLS 协议版本与对称加密套件。"],
    ["tcpfp", "net", "TCP SYN 被动协议栈系统", false, "服务端直接抓包读取首个 TCP SYN 包的初始 TTL（Windows=128，macOS/Linux=64）、跳数与选项排列推断真实发包内核。"],
    ["ipquirk", "net", "IP 层 DF/IPID/ECN 与内核时钟", false, "深度解析 IPv4 DF 不分片位、SYN→Hello IPID 步进策略、ECN 拥塞标记与 TCP TSval 时间戳频率（Hz），专抓无状态 NFQUEUE 改包伪造。"],
    ["ja4t", "net", "TCP 窗口、MSS 与 JA4T 指纹", false, "由 TCP 初始接收窗口、选项序列编码、MSS 与窗口缩放因子组成的传输层指纹 JA4T。"],
    ["tunnel", "net", "链路 MTU 与 VPN 隧道特征", false, "由 TCP MSS 反推路径 MTU：1500 为标准以太网，1492 为 PPPoE，1420/1280 常为 WireGuard/TUN 隧道，>1500 为云内网巨型帧。"],
    ["ja4", "net", "TLS ClientHello 指纹 (JA4)", false, "从原始 TLS 握手首包提取加密套件、扩展与签名算法计算的行业标准 JA4 指纹。"],
    ["ja3", "net", "TLS JA3 哈希与 GREASE", false, "经典 MD5 格式 JA3 TLS 指纹，以及是否包含浏览器特有的 RFC 8701 GREASE 随机注入值。"],
    ["tlsperm", "net", "TLS 扩展随机重排与 PSK 验真", false, "按 ClientHello.random 比对同一访客连续两次独立 TLS 握手的扩展序列：Chrome 110+ 每次连接随机洗牌扩展顺序，若连续两次扩展排列 100% 死板雷同，即暴露静态 JA3 / uTLS 伪造模板。"],
    ["tlsext", "net", "TLS 浏览器专属扩展特征", false, "检查 ALPS 应用层设置扩展与 Brotli 证书压缩扩展，真浏览器具备而 curl/Go/Python 脚本通常缺失。"],
    ["pqkex", "net", "后量子密钥交换 (PQ-KEM)", false, "检查 TLS ClientHello KeyShare 是否启用抗量子计算破解的 X25519MLKEM768 混合密钥交换。"],
    ["ech", "net", "加密 ClientHello (ECH)", false, "检查 TLS 握手是否携带 0xfe0d ECH 扩展以加密保护目标域名 SNI。"],
    ["reality443", "net", "出口 :443 反向握手与 Reality 验真", false, "主动回探出口公网 IP 的 443 端口：若非微软/苹果/雅虎等大厂 ASN 却返回其有效证书或通过严格 SNI 签名校验，即可实锤 VLESS-Reality / ShadowTLS 偷证书伪装。"],
    ["portscan", "net", "出口 IP 实时代理 / 远控端口回扫", false, "服务端对当前出口 IP 并发 TCP connect 17 个常见代理（SOCKS / Squid / Shadowsocks / Clash / V2Ray / Tor）、VPN（OpenVPN / PPTP）、远控（SSH / RDP / VNC）与面板（X-UI）端口，仅被动读取欢迎横幅、不发送任何载荷；家宽与蜂窝 NAT 出口几乎从不开放这些端口。出于防滥用，仅对访客自身出口执行。"],
    ["h2fp", "net", "HTTP 请求头序签名", false, "不同浏览器内核发送请求头的先后顺序各自固定，改 UA 插件无法改变底层发包头顺序。"],
    ["h2akamai", "net", "HTTP/2 Akamai 原始帧指纹", false, "服务端在 TLS 解密首包无损解析 HTTP/2 SETTINGS 参数顺序与值、连接级 WINDOW_UPDATE 增量、流优先级与 HPACK 伪头部排列顺序（如 Chrome 为 m,a,s,p，Firefox 为 m,p,a,s，Safari 为 m,s,p,a），专抓改 UA 与 Go/Python/curl 协议库伪装。"],
    ["quicfp", "net", "HTTP/3 (QUIC / UDP 443) 探测", false, "结合边缘协商与 ResourceTiming 检测当前网络及代理链路是否放行基于 UDP 443 的 QUIC 协议。"],
    ["quicpar", "net", "QUIC Initial 解密与传输参数 (JA4Q)", false, "触发原生 WebTransport QUIC v1 握手，服务端利用 RFC 9001 公开初始盐无私钥解密多包 CRYPTO 帧，提取 JA4Q 与 quic_transport_parameters（流控窗口、GREASE 位等），识别 Chromium quiche、Firefox neqo、Apple nw_quic 与代理 quic-go。"],
    ["dns", "net", "递归 DNS 解析器出口", true, "生成随机一次性子域名触发真实递归查询，定位替你解析域名的上游 DNS 服务器国家与运营商。"],
    ["ecs", "net", "多路递归 DNS 集群与 ECS 归属", true, "并发探测上游 DNS 集群节点并核验 EDNS Client Subnet (ECS) 子网透传及运营商同源性（本网 ISP / 公共 Anycast / 跨境泄漏）。"],
    ["webrtc", "net", "WebRTC STUN 公网地址", true, "通过 STUN 协议在 UDP 通道探测本机反射出的真实公网 IPv4/IPv6 地址，未开 TUN 的代理常在此漏底。"],
    ["rtcsdp", "net", "WebRTC SDP 协议栈与 SCTP 模板", false, "纯本地生成 RTCPeerConnection Offer SDP（不连外网），提取 ice-options、DTLS 指纹哈希算法、SCTP max-message-size 与 RTP 扩展模板签名，区分 libwebrtc、WebKit 与 Gecko 真实媒体栈。"],
    ["ufrag", "net", "SDP ice-ufrag 长度与 Origin 引擎互证", false, "核验 SDP Offer 的 o= Origin 签名（Firefox 必含 THIS_IS_SDPARTA）与 a=ice-ufrag 随机串长度（Chromium libwebrtc 恒为 4 字符，Firefox nICEr 为 8 字符），专杀 Chromium 套壳伪装 Firefox 或 Camoufox 伪装 Chrome。"],
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
    ["rttgeo", "exit", "全球 18 区域 RTT 光速三角测距", false, "浏览器对 AWS 全球 18 个区域（含北京）端点做热连接往返测距，找出物理最近区域；若某区域往返低于「出口 IP 登记地 → 该区域」的光纤物理下限（≈ 距离 / 100 ms），即证明该路流量并未经过当前出口（规则分流）或出口 IP 属跨洲广播段。"],
    ["aigeo", "exit", "AI / 社媒平台地区准入 (OpenAI·Claude·Gemini·TikTok)", false, "按 ChatGPT、Claude 等平台各自实际分流出口的国家，比对 OpenAI、Anthropic、Google Gemini 与 TikTok 官方不提供服务的地区（参考名单），避免注册或登录时直接被 unsupported_country 拦截。"],

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
    ["proxyhdr", "hdr", "代理转发头与 HTTPS 中间人注入", false, "TLS 已在本站终止，浏览器原生绝不会发送 Via / Forwarded / 预置 X-Forwarded-For 跳数 / CF-Worker 等头；一旦出现，说明请求经过了 HTTPS 解密代理、企业网关、杀软 Web 防护或 Cloudflare Worker 反代。"],
    ["h_lfmt", "hdr", "Accept-Language q 权重格式核验", false, "校验 HTTP 语言头 q 权重是否严格递减、格式合法，且不含 JS navigator.languages 之外的语种——ModHeader 类插件或中间层改写语言头时常在此露馅。"],
    ["chgrease", "hdr", "Sec-CH-UA GREASE 品牌算法校验", false, "Chromium 以主版本号为种子生成 \"Not?A?Brand\" 伪品牌与版本（8 / 99 / 24）；改 UA 工具与指纹浏览器常沿用旧格式或乱填，本探针按算法复算并比对 HTTP 头与 JS userAgentData。"],

    // Group 5: loc (11)
    ["langs", "loc", "navigator.languages 语言列表", false, "JS 读取的浏览器首选与备选语言全列表，反映用户日常阅读语种。"],
    ["locale", "loc", "Intl 默认区域与历法", false, "国际化引擎默认解析出的区域代码、日历体系与数字书写系统。"],
    ["tz", "loc", "系统 IANA 时区名称", false, "Intl.DateTimeFormat 读取的操作系统时区 ID（如 Asia/Shanghai）及当前标准时间名。"],
    ["tzoff", "loc", "Date 与 Intl 双源时区校验", false, "交叉核对 Date.prototype.getTimezoneOffset() 与 Intl 时区偏移，劣质改时区插件常只改其一。"],
    ["tzdst", "loc", "夏令时规则与历史时区偏移核验", false, "对今年冬/夏季及 2005、2015 年多个时间点分别用 Date.getTimezoneOffset 与 Intl IANA 规则计算偏移；只 Hook 固定偏移的改时区插件会在夏令时切换或历史规则上露馅。"],
    ["clocksrc", "loc", "Date 时钟源内部一致性", false, "比对 Date.now()、new Date()、Date.parse(ISO) 与 performance 单调时钟，并与服务端校时交叉印证；libfaketime / 改时间插件只 Hook 部分接口时会出现秒级断裂。"],
    ["tzname", "loc", "Date 时区名称语言（界面语言泄露）", false, "new Date().toString() 括号内的时区名由浏览器界面 / ICU 默认语言决定（如「中国标准时间」），与 navigator.languages 独立；改了语言列表却没改界面语言时会在此露出原始语种。"],
    ["hour", "loc", "默认时钟制式（12/24 小时）", false, "当前语言区域默认采用的小时计数制式及本地格式化时间样本。"],
    ["week", "loc", "每周起始日习惯", false, "Intl.Locale.weekInfo 暴露的一周第一天（如中国/欧洲为周一，美国/日本多为周日）。"],
    ["fmt", "loc", "数字分组与日期格式", false, "本地化长数字千分位小数点样式与年月日排列格式。"],
    ["icu", "loc", "浏览器 ICU 国际化字典规模", false, "统计 Intl.supportedValuesOf 支持的时区、货币、度量单位与历法总数，精简版或旧版内核数量明显不同。"],
    ["intlcoll", "loc", "ICU 默认排序规则与列表语法", false, "测试 Intl.Collator 对汉字拼音/笔画与拉丁变音字符的默认排序顺序及 ListFormat 连接词，识破未改透的区域伪装。"],
    ["intldeep", "loc", "Intl 六大构造器默认区域一致性", false, "交叉核对 DateTimeFormat、NumberFormat、RelativeTimeFormat、PluralRules、DisplayNames 与 ListFormat 的默认语言区域，抓捕只 Hook 部分国际化接口的改语言插件。"],
    ["kbd", "loc", "物理键盘键位布局", false, "通过 navigator.keyboard.getLayoutMap 静默识别 QWERTY、AZERTY（法语）、QWERTZ（德语）等物理键位。"],
    ["voices", "loc", "系统内置离线朗读语音包", false, "枚举 speechSynthesis 本地语音合成引擎，Windows 系统安装的语言包会在此留下明确语种痕迹。"],

    // Group 6: dev (35)
    ["os", "dev", "真实操作系统与版本", false, "结合高熵 Client Hints 与 Windows 系统专属字体反证（识别伪造 Win11 的旧系统）还原真实 OS 版本。"],
    ["browser", "dev", "浏览器品牌与版本新旧度", false, "解析真实浏览器品牌、主版本号，并推算距离当前最新正式版落后几个版本周期。"],
    ["arch", "dev", "CPU 指令集架构与位数", false, "处理器底层架构（arm / x86）与 64/32 位运行环境。"],
    ["cpu", "dev", "CPU 逻辑核心线程数", false, "navigator.hardwareConcurrency 暴露的处理器逻辑线程数量。"],
    ["cpubench", "dev", "WASM SIMD 指令集与虚拟化抢占抖动", false, "校验真实 WebAssembly 128-bit SIMD 字节码支持度，并采样 60 组微时间片算力延迟比 (p99/p50)，捕捉云服务器/虚拟机 Hypervisor CPU Steal 毛刺。"],
    ["jitwarm", "dev", "JS 引擎 JIT 编译预热加速曲线", false, "对比同一纯算术热函数冷态（解释器）与 15,000 次迭代后（Maglev / TurboFan / FTL 机器码）的单轮执行加速倍数，识别 iOS 锁定模式、容器禁用 JIT (W^X) 或跨架构 QEMU 转译。"],
    ["mem", "dev", "物理内存档位 (deviceMemory)", false, "Chromium 浏览器按分档上报的本机物理内存容量下限（最大封顶报 8 GB）。"],
    ["heap", "dev", "V8 单页 JS 堆内存上限", false, "performance.memory.jsHeapSizeLimit 暴露的单标签页最大可用内存（64 位桌面通常约 4.0 GB）。"],
    ["screen", "dev", "屏幕真实物理像素分辨率", false, "结合 CSS 像素与 devicePixelRatio 反算显示器面板原生物理像素（如 Mac Retina 2940×1912）。"],
    ["hz", "dev", "显示器物理刷新率 (Hz)", false, "通过连续 40 帧 requestAnimationFrame 时间间隔中位数实测屏幕真实刷新率（60 / 120 / 144 / 240 Hz）。"],
    ["screens", "dev", "多显示器扩展状态与窗口坐标", false, "screen.isExtended 检测是否连接了多块屏幕，并记录当前窗口在桌面坐标系中的位置。"],
    ["gamut", "dev", "屏幕色域与 HDR 动态范围", false, "CSS 媒体查询探测显示器色彩空间（Display P3 / Rec.2020 / sRGB）与高动态范围 (HDR) 能力。"],
    ["touch", "dev", "触控点数与输入指针类型", false, "最大同时触控点数与主输入设备精度（精细鼠标触控板 vs 粗粒度手指触屏）。"],
    ["uigeom", "dev", "原生表单控件亚像素包围盒几何", false, "测量未加样式的原生 button / select / checkbox / range 控件宽高，macOS Cocoa、Windows Fluent 与 Linux GTK 原生主题尺寸截然不同。"],
    ["mqscreen", "dev", "CSS 媒体查询 vs JS 屏幕读数", false, "用 device-width / device-height / resolution / orientation 媒体查询二分反推渲染引擎眼中的真实屏幕，与 JS screen.width / devicePixelRatio 比对；只改 JS 属性的指纹插件无法同步伪造媒体查询。"],
    ["mobilex", "dev", "移动端仿真一致性", false, "核对 UA 自称的手机/平板身份与触控点数、主指针精度、悬停能力、触摸事件、屏幕短边与 GPU 型号是否自洽，识别桌面 DevTools 设备模拟与改 UA 冒充手机。"],
    ["fontrast", "dev", "跨系统字体光栅化引擎签名", false, "分析斜线与曲线字形边缘的 RGB 彩边离差与灰阶 Gamma 分布，识破在 Linux/Windows 容器强装苹果 PingFang 字体伪装 Mac 的行为。"],
    ["gpu", "dev", "显卡真实型号与双显卡探测", false, "同时请求默认与 high-performance 上下文，挖掘核显笔记本背后隐藏的独立显卡型号及虚拟机软件渲染特征。"],
    ["glx", "dev", "WebGL 版本与纹理能力上限", false, "WebGL 1/2 支持状态、最大纹理像素尺寸及显卡驱动暴露的扩展总数。"],
    ["gpufp", "dev", "GPU 着色器尾数与压缩纹理架构核验", false, "运行 highp 片元着色器提取 GPU ALU 超越函数硬件舍入尾数，并核对压缩纹理硬件格式（Apple M 系必含 ASTC，桌面 NVIDIA/AMD 含 S3TC/BPTC 不含 ASTC），识破仅篡改显卡名称字符串的伪装。"],
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
    ["stackfmt", "dev", "Error 调用栈语法与引擎互证", false, "解析原生 Error.prototype.stack 行缩进语法（V8 的 '    at ' vs SpiderMonkey/JSC 的 '@'）及结构化堆栈接口，反证跨浏览器内核的 UA 伪装。"],
    ["wasmfeat", "dev", "WebAssembly 特性矩阵与内核代际", false, "逐项校验 13 项 WASM 提案字节码（SIMD、异常处理、尾调用、GC、Relaxed SIMD、线程等）与 JSPI，按各特性正式上线版本反推 V8 / SpiderMonkey 真实代际，拆穿虚报新版 UA 的旧内核。"],
    ["fontlocal", "dev", "FontFace local() 字体旁路核验", false, "绕过 Canvas 字宽测量，直接用 CSS Font Loading API 的 local() 加载 17 款系统标志性字体，与 Canvas 字体探测交叉比对，识破只 Hook measureText 的字体伪装与跨系统虚报。"],
    ["cpuarch", "dev", "浮点 NaN 位模式 CPU 架构", false, "Infinity − Infinity 生成的 NaN 在 x86 与 ARM 上高字节不同（0xFF vs 0x7F），与 Client Hints / UA 自报架构比对，可识破手机 UA 跑在 x86 模拟器 / 云手机上的情形（FingerprintJS architecture 同款）。"],
    ["sysfont", "dev", "CSS 系统字体关键字与系统色", false, "解析 font: caption / menu / message-box 等系统字体关键字与 Canvas / Highlight / AccentColor 等系统色，渲染引擎直接取自宿主操作系统，可反证伪装系统（CreepJS 同款）。"],
    ["navprops", "dev", "navigator 厂商属性一致性", false, "核对 vendor、productSub、eval.toString 长度、appVersion、oscpu / buildID、userAgentData、H.264 专利解码与 15 种厂商全局对象（FingerprintJS vendorFlavors）是否与自报浏览器一致——Akamai / BotD 同款检查。"],
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
    ["cdp", "brw", "CDP 调试协议附着与注入帧", false, "给 Error 安装 stack getter 后调用 console.debug：只有 Chrome DevTools Protocol 的 Runtime 域被启用（开发者工具打开 / Puppeteer / Playwright 控制）时才会序列化触发；并扫描注入脚本帧、Selenium DOM 标记与无头通知权限矛盾。"],
    ["winchrome", "brw", "窗口外框与无头渲染尺寸", false, "对比 outerWidth/outerHeight 与视口尺寸：无头 Chrome 外框为 0 或与视口完全相同，开发者工具停靠会产生异常巨大的外框差（已排除页面缩放与全屏干扰）。"],
    ["incog", "brw", "无痕 / 隐私浏览窗口识别", false, "Chromium 依据临时存储配额与 JS 堆上限比值、Safari 依据 OPFS getDirectory 异常、Firefox 依据存储 SecurityError 判断当前是否处于无痕窗口。"],
    ["input", "brw", "交互事件可信度与轨迹", false, "捕获检测期间全部鼠标 / 触摸 / 键盘事件：isTrusted=false 的合成事件直接实锤脚本操控，并统计鼠标轨迹机械直线占比（检测期间未操作属正常）。"],
    ["biodyn", "brw", "精细行为生物动力学 (加加速度/滚轮/键驻留)", false, "分析鼠标速度变异系数与加加速度 (Jerk) 熵、区分触控板连续惯性流与机械滚轮 100/120px 离散步进，并统计按键 keydown→keyup 驻留时间（Akamai sensor_data 同款行为维度）。"],
    ["autokeys", "brw", "自动化 / 爬虫框架全局标记全量扫描", false, "扫描 Selenium / ChromeDriver($cdc_) / Watir / PhantomJS / Nightmare / Cypress / TestCafe / WebdriverIO / Playwright / Puppeteer exposeFunction / CEF / CefSharp / Awesomium / Sequentum 等 60 余个全局变量与 document 标记（BotD、PerimeterX、Akamai、TikTok 风控同款清单）。"],
    ["jsenv", "brw", "宿主运行时（Node / Electron / jsdom / WebView）", false, "检测 process / Buffer / require / global 等 Node 全局、Electron 与 NW.js、jsdom UA，以及 WKWebView / React Native / Flutter / 微信 JSBridge 等应用内容器——TikTok webmssdk 会据此区分真实浏览器与脚本宿主。"],
    ["headless", "brw", "无头浏览器渲染特征", false, "HeadlessChrome 品牌、破损图片 0×0（旧版无头）、plugins 与 PDF 查看器矛盾、connection.rtt=0、语音引擎为空、软件 GPU 与 800×600 / 1280×720 默认视口（CreepJS、Sannysoft、BotD 同款；ActiveText 系统色仅记录，现代 Chrome 已不再区分）。"],
    ["stealth", "brw", "隐身补丁残留（stealth / undetected）", false, "puppeteer-extra-stealth、undetected-chromedriver 与指纹浏览器常见破绽：webdriver 被删成 undefined、window.chrome 事后注入或函数伪造、srcdoc iframe 代理回主窗口、原生 getter 错误栈出现 Proxy 帧、伪造 PluginArray。"],
    ["focus", "brw", "页面焦点、可见性与用户激活", false, "document.hasFocus()、visibilityState 与 navigator.userActivation：无头或后台自动化常见「页面可见却从未获得焦点、也从无用户手势」。"],
    ["ipcflood", "brw", "IPC 洪泛保护开关 (replaceState)", false, "在隐藏同源空白 iframe 内瞬时调用 260 次 history.replaceState（约 12ms，不改主页面 URL）：正常 Chromium 在 200 次处触发限流保护，而 Puppeteer / Playwright 默认启动参数 --disable-ipc-flooding-protection 会全量放行。"],
    ["cspbypass", "brw", "CSP 内容安全策略绕过检测", false, "在隔离 srcdoc iframe 内设置 script-src 'none' 并放置探针内联脚本：正常浏览器 100% 拦截，开启 Playwright bypassCSP 或 CDP Page.setBypassCSP 时脚本会违规执行。"],
    ["popupblk", "brw", "弹窗拦截策略开关 (popup-blocking)", false, "在页面首次无用户激活手势阶段静默测试 window.open 是否被浏览器默认拦截（若打开则毫秒级立即关闭），识别自动化框架默认参数 --disable-popup-blocking。"],
    ["glworker", "brw", "Worker OffscreenCanvas 显卡跨线程核验", false, "在独立 Web Worker 线程内通过 OffscreenCanvas 读取 WebGL 真实显卡渲染器并与主线程对比，专杀只篡改主页面 WebGL 的 stealth 插件与指纹浏览器（CreepJS hasBadWebGL 同款）。"],
    ["adblock", "brw", "广告拦截插件双重实测", false, "结合页面多类名广告 DOM 诱饵隐藏检测与 Google 广告脚本网络请求拦截对照（排除断网误判）。"],
    ["ext", "brw", "页面注入痕迹识别扩展", false, "检测加密钱包全局对象（MetaMask/OKX/Phantom/Rabby）、DevTools 钩子与翻译/暗色插件 DOM 标记。"],
    ["extwar", "brw", "Chrome 扩展公开资源扫描", false, "并发探测 36 款主流代理、改指纹、脚本管理器、钱包与密码管理扩展暴露的 chrome-extension:// 静态资源。"],
    ["worker", "brw", "Web Worker 线程交叉核验", false, "启动独立 Worker 线程读取 navigator 与时区，与主线程逐项对比，专抓只改主页面的防关联插件。"],
    ["swrealm", "brw", "SharedWorker 与 ServiceWorker 核验", false, "并发拉起第 4 界 SharedWorker 与第 5 界 ServiceWorker（采完即注销零残留），交叉比对 UA、平台、核数、语言、时区与显卡，抓捕漏改共享/服务线程的指纹浏览器。"],
    ["iframe", "brw", "洁净 iframe 沙箱交叉核验", false, "动态创建空白同源 iframe 对照 navigator、screen 与时区读数，识别页面级浅层注入。"],
    ["lies", "brw", "52 项原生接口谎言检测", false, "利用洁净 iframe 的 Function.toString、prototype 属性检查与非法调用异常测试，抓捕被重写过的原生 API。"],
    ["shield", "brw", "防指纹护盾品牌归因", false, "根据加噪方式与特征识别 Brave Farbling、Firefox RFP、Safari 高级防追踪或第三方改指纹扩展。"],
    ["trackers", "brw", "7 大追踪器拦截实测（手动）", false, "点击按钮后向 Google Analytics、DoubleClick、Meta、Bing、TikTok、百度统计、Hotjar 发起无 Cookie 测试请求。"],
    ["localport", "brw", "本机代理与指纹浏览器端口自检（手动）", false, "仅在手动点击时探测 127.0.0.1 上的 Clash/Mihomo (7890/7891/9090)、v2rayN (10808)、AdsPower (50325)、比特浏览器 (54345)、Multilogin (35000) 与 Chrome 调试口 (9222)，绝不自动弹窗打扰正常访客。"],

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
    ["audiolat", "fp", "AudioContext 基础延迟指纹", false, "AudioContext.baseLatency / outputLatency 与采样率由操作系统音频栈决定（如 macOS 256 帧、Windows 480 帧），属 FingerprintJS 稳定指纹源之一。"],
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
    ["reality", "出口主动回探（:443 Reality 与代理端口）", ["disguise"]],
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
  const MOBILE_RE = /\b5gc\b|\b5g\b|\b4g\b|\blte\b|cellular|mobile|mobility|wireless|cmnet|cmiot|chinamobile|china mobile|unicom mobile|t-mobile|verizon wireless|at&t mobility|docomo|kddi|vodafone/i;
  function isMobileIp(geo) {
    if (!geo) return false;
    const hay = [geo.isp, geo.org, geo.asFull, geo.asName, geo.ptr].filter(Boolean).join(" ");
    return !!(geo.mobile || MOBILE_RE.test(hay));
  }
  function cleanIp(raw) {
    let s = String(raw || "").trim();
    if (!s) return "";
    if (s.startsWith("[")) {
      const close = s.indexOf("]");
      s = close > 0 ? s.slice(1, close) : s.replace(/^\[+|\]+$/g, "");
    }
    const pct = s.indexOf("%");
    if (pct > 0) s = s.slice(0, pct);
    return s.includes(":") ? s.toLowerCase() : s;
  }

  const RELAY4 = [[104, 28], [172, 224], [172, 225], [172, 226], [146, 75], [140, 248]];
  function isAppleRelay(ip) {
    const s = cleanIp(ip);
    if (!s) return false;
    if (s.includes(":")) return /^(2606:54c[03]|2a02:26f7|2a04:4e41|2a09:bac[23]):/i.test(s);
    const [a, b] = s.split(".").map(Number);
    return RELAY4.some(([x, y]) => x === a && y === b);
  }

  function expandV6(ip) {
    const s = cleanIp(ip);
    const [h, tl = ""] = s.split("::");
    const H = h ? h.split(":") : [], T = tl ? tl.split(":") : [];
    return [...H, ...Array(Math.max(0, 8 - H.length - T.length)).fill("0"), ...T].map(g => g.padStart(4, "0"));
  }
  function extractV6Mac(ip) {
    const s = cleanIp(ip);
    if (!s || !s.includes(":")) return null;
    const g = expandV6(s).map(x => parseInt(x, 16));
    if ((g[5] & 0xff) !== 0xff || (g[6] >> 8) !== 0xfe) return null;
    const b = [(g[4] >> 8) ^ 0x02, g[4] & 0xff, g[5] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
    return b.map(x => x.toString(16).padStart(2, "0")).join(":");
  }
  function netPrefix(ip) {
    const s = cleanIp(ip);
    if (!s) return "";
    return s.includes(":") ? expandV6(s).slice(0, 4).join(":") : s.split(".").slice(0, 2).join(".");
  }

  function normalizeCarrierKey(info = {}) {
    const ip = cleanIp(info.ip).toLowerCase();
    const asnNum = String(info.asn || "").replace(/^AS/i, "").trim();
    const hay = [info.isp, info.org, info.asFull, info.asName, info.label].filter(Boolean).join(" ").toLowerCase();
    if (
      /^240e:/.test(ip) ||
      /^(4134|4809|4812|4816|58466|134764|140486)$/.test(asnNum) ||
      /chinanet|china ?telecom|chinatelecom|\bctcc\b|中国电信|电信/.test(hay)
    ) return "cn-telecom";
    if (
      /^2409:8/.test(ip) ||
      /^(9808|24400|24547|56040|56041|56042|56044|56046|56047|56048)$/.test(asnNum) ||
      /china ?mobile|chinamobile|cmnet|cmiot|中国移动|移动/.test(hay)
    ) return "cn-mobile";
    if (
      /^2408:8/.test(ip) ||
      /^(4837|10099|17621|17622|17623|17816)$/.test(asnNum) ||
      /china ?unicom|china169|unicom|uninet|中国联通|联通/.test(hay)
    ) return "cn-unicom";
    if (/^240c:|^2001:da8:/.test(ip) || /^4538$/.test(asnNum) || /cernet|教育网/.test(hay)) return "cn-cernet";
    const cleaned = hay
      .replace(/\bas\d+\b/g, " ")
      .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, " ")
      .split(/\s+/)
      .filter(w => w.length >= 3 && !/^(the|inc|llc|ltd|corp|corporation|company|co|communications|communication|telecom|telecommunications|network|networks|holdings|group|province|city|broadband|internet|services|service|wireless|mobile|mobility|cellular|5gc|data|technology|technologies)$/.test(w));
    if (cleaned.length) return `org:${cleaned[0]}`;
    if (asnNum) return `as:${asnNum}`;
    return "";
  }

  function isTcpOsMismatch(tcp, uaOs) {
    if (!tcp) return false;
    const tcpFam = tcp.osFamily || tcp.osGuess;
    const claimApple = /^(macOS|iOS|iPadOS)$/.test(uaOs || "");
    const claimWin = uaOs === "Windows";
    return (
      (tcpFam === "windows" && !claimWin) ||
      (tcpFam === "apple" && !claimApple) ||
      (tcpFam === "linux" && (claimApple || claimWin))
    );
  }

  function isCellularNativeLink(uaOs, osMismatch) {
    if (osMismatch || R.netKind === "dc" || R.netKind === "relay") return false;
    if (R.netKind === "mobile") return true;
    try {
      if (navigator.connection && navigator.connection.type === "cellular") return true;
    } catch (e) {}
    if (/^(iOS|Android|HarmonyOS)$/.test(uaOs || "") && R.ipCC && (!R.tz || tzCC(R.tz) === R.ipCC)) {
      return true;
    }
    return false;
  }

  function isMuxTunnelSuspect(mux) {
    if (!mux) return false;
    const rawCoalesced = mux.coalescedPairs >= 3 || (mux.srvSpanMs < mux.clientSpanMs * 0.35 && mux.clientSpanMs >= 30);
    if (!rawCoalesced) return false;

    const tcp = R.srv?.packet?.tcp || null;
    const uaOs = R.dev?.os || "";
    const osMis = isTcpOsMismatch(tcp, uaOs);
    const nonProxyNet =
      R.netKind !== "dc" &&
      R.netKind !== "relay" &&
      (R.intel?.votes?.hosting?.E || 0) < 0.45 &&
      (R.intel?.votes?.proxy?.E || 0) < 0.35 &&
      (R.intel?.votes?.vpn?.E || 0) < 0.35;

    // 服务端旁路握手 RTT 与浏览器 HTTP RTT 吻合且端侧原生协议栈一致：物理证明中间无代理隧道，微脉冲合并属无线空口或 HTTP/2 按序重组
    if (tcp && !osMis && nonProxyNet && R.srvTcpRtt != null && R.httpRtt != null && (R.httpRtt - R.srvTcpRtt) < 35) {
      return false;
    }

    // 4G/5G 蜂窝空口 (3GPP NR 上行时隙授权 + RLC/HARQ 重传) 在连接复用时天然存在 2~4 对微脉冲同帧到达
    if (isCellularNativeLink(uaOs, osMis) && nonProxyNet) {
      return mux.coalescedPairs >= 5 && mux.srvSpanMs < mux.clientSpanMs * 0.18;
    }

    return true;
  }

  function candidateCC(rawCandIp) {
    const candIp = cleanIp(rawCandIp);
    if (!candIp) return "";
    const meta = R.ipMeta?.[candIp] || R.ipMeta?.[rawCandIp] || null;
    const matchedExit = Object.values(R.exits || {}).find(x => x && cleanIp(x.ip) === candIp);
    return meta?.cc || matchedExit?.cc || (/^240[89ce]:/i.test(candIp) ? "CN" : "");
  }

  function isSameCarrierCandidate(rawCandIp) {
    const candIp = cleanIp(rawCandIp);
    const selfIp = cleanIp(R.ip);
    if (!candIp || !selfIp) return false;
    if (candIp === selfIp) return true;
    if (netPrefix(candIp) && netPrefix(candIp) === netPrefix(selfIp)) return true;
    if (R.netKind === "dc" || R.netKind === "relay") return false;

    const meta = R.ipMeta?.[candIp] || R.ipMeta?.[rawCandIp] || null;
    if (meta?.hosting) return false;
    const matchedExit = Object.values(R.exits || {}).find(x => x && cleanIp(x.ip) === candIp);
    const candCC = candidateCC(candIp);
    if (!candCC || !R.ipCC || candCC !== R.ipCC) return false;

    const exitKey = normalizeCarrierKey({
      ip: selfIp,
      asn: R.asn,
      org: R.org,
      isp: R.srv?.geo?.isp,
      asFull: R.srv?.geo?.asFull,
      asName: R.srv?.geo?.asName
    });
    const candKey = normalizeCarrierKey({
      ip: candIp,
      asn: meta?.asn,
      org: meta?.org,
      isp: meta?.isp,
      asFull: meta?.asFull,
      label: matchedExit?.label
    });
    if (exitKey && candKey && exitKey === candKey) return true;
    if (meta?.asn && R.asn && String(meta.asn).replace(/^AS/i, "") === String(R.asn).replace(/^AS/i, "")) return true;
    if ((candIp === cleanIp(R.stack?.v4) || candIp === cleanIp(R.stack?.v6)) && (!candKey || !exitKey)) return true;
    return false;
  }

  function getLeakedWebrtcIps() {
    const rtcList = Array.isArray(R.rtc) ? R.rtc : [];
    if (!rtcList.length || !R.ip) return [];
    return rtcList.filter(ip => !isSameCarrierCandidate(ip));
  }

  function isSafariSubprobeRelay(key, v) {
    if (!v || !v.ip || key === "ex_self" || key === "ex_cn") return false;
    if (!isAppleRelay(v.ip)) return false;
    if ((v.warp && v.warp !== "off") || (R.cfEdge?.warp && R.cfEdge.warp !== "off")) return false;
    if (!/^(iOS|iPadOS|macOS)$/.test(R.dev?.os || "") && R.engine !== "JavaScriptCore") return false;
    if (R.ip && isAppleRelay(R.ip)) return false;
    return true;
  }

  function analyzeExitSplit() {
    const ex = R.exits || {};
    const allValidExits = Object.entries(ex).filter(([, v]) => v && v.ip);
    const cnIp = ex.ex_cn;
    const cnLeak = !!(cnIp && cnIp.cc === "CN" && R.ipCC && R.ipCC !== "CN");
    if (cnLeak) {
      const allCountries = new Set(allValidExits.map(([, v]) => v.cc).filter(Boolean));
      return { state: "cn-leak", countries: allCountries, distinctCount: Math.max(2, allCountries.size), validExits: allValidExits };
    }
    const relayedSubprobes = allValidExits.filter(([k, v]) => isSafariSubprobeRelay(k, v));
    const filteredExits = relayedSubprobes.length ? allValidExits.filter(([k, v]) => !isSafariSubprobeRelay(k, v)) : allValidExits;
    const validExits = filteredExits.length ? filteredExits : allValidExits;
    const countries = new Set(validExits.map(([, v]) => v.cc).filter(Boolean));
    if (countries.size > 1) {
      return { state: "multi-country", countries, distinctCount: countries.size, validExits };
    }
    const v4Prefixes = new Set(validExits.filter(([, v]) => !cleanIp(v.ip).includes(":")).map(([, v]) => netPrefix(v.ip)).filter(Boolean));
    const v6Prefixes = new Set(validExits.filter(([, v]) => cleanIp(v.ip).includes(":")).map(([, v]) => netPrefix(v.ip)).filter(Boolean));
    const hasUnalignedExit = validExits.some(([k, v]) => k !== "ex_self" && netPrefix(v.ip) !== netPrefix(R.ip) && !isSameCarrierCandidate(v.ip));
    if ((v4Prefixes.size > 1 || v6Prefixes.size > 1) && hasUnalignedExit) {
      return { state: "multi-prefix", countries, distinctCount: v4Prefixes.size + v6Prefixes.size, validExits };
    }
    if (v4Prefixes.size >= 1 && v6Prefixes.size >= 1 && hasUnalignedExit) {
      return { state: "dual-stack-mismatch", countries, distinctCount: 2, validExits };
    }
    return {
      state: "ok",
      dualStackAligned: v4Prefixes.size >= 1 && v6Prefixes.size >= 1,
      cgnatAligned: v4Prefixes.size > 1 || v6Prefixes.size > 1,
      safariRelayCount: relayedSubprobes.length,
      countries,
      distinctCount: 1,
      validExits
    };
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
  let activeWorkspaceTab = "checks";
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

  function switchWorkspaceTab(tabId, opts = {}) {
    if (!tabId) return;
    activeWorkspaceTab = tabId;
    $$("#workspaceTabs .ws-tab").forEach(btn => {
      const on = btn.dataset.wstab === tabId;
      btn.setAttribute("aria-selected", on ? "true" : "false");
      btn.tabIndex = on ? 0 : -1;
      btn.className = "ws-tab shrink-0 min-w-0 py-2 px-2 sm:px-3.5 inline-flex items-center justify-center gap-1.5 sm:gap-2 rounded-lg text-xs transition " + (
        on
          ? "font-semibold bg-white text-zinc-950 shadow-2xs dark:bg-zinc-800 dark:text-white"
          : "font-medium text-zinc-600 hover:text-zinc-950 dark:text-zinc-400 dark:hover:text-zinc-100"
      );
    });
    $$("[data-wspanel]").forEach(panel => {
      panel.hidden = panel.dataset.wspanel !== tabId;
    });
    // 吸顶标签栏已贴住顶部时，切换后把新面板顶部带回视口，避免停留在旧面板的滚动深处
    const bar = $("#workspaceBar");
    if (opts.keepScroll || !bar) return;
    const hdrH = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--hdr-h")) || 0;
    if (bar.getBoundingClientRect().top <= hdrH + 2) {
      const sec = bar.parentElement;
      const y = sec.getBoundingClientRect().top + window.scrollY - hdrH - 6;
      window.scrollTo({ top: y, behavior: mq("(prefers-reduced-motion: reduce)") ? "auto" : "smooth" });
    }
  }

  /* ---------- Check card visual tokens (shared by live run & shared snapshot) ---------- */
  function ckCardClass(level, active) {
    const issue = level === "bad" || level === "warn";
    const stripe = level === "bad"
      ? "border-l-[3px] border-l-rose-500"
      : level === "warn"
      ? "border-l-[3px] border-l-amber-500 dark:border-l-amber-400"
      : "border-l-zinc-200/80 dark:border-l-white/[0.07]";
    return `ck-card group rounded-xl border border-zinc-200/80 bg-white ${stripe} ${issue ? "px-4 py-3" : "px-4 py-2.5"} cursor-pointer transition-colors hover:bg-zinc-50/70 dark:bg-[#151820] dark:border-white/[0.07] dark:hover:bg-[#181b24] ${active ? "" : "opacity-50"}`;
  }
  function ckValClass(level, expanded) {
    const issue = level === "bad" || level === "warn";
    return `ck-val maskable mt-1 text-xs leading-relaxed ${issue ? "text-zinc-700 dark:text-zinc-300" : "text-zinc-500 dark:text-zinc-400"} ${expanded ? "" : issue ? "line-clamp-3 sm:line-clamp-2" : "truncate"}`;
  }
  function ckTitleClass(level) {
    const issue = level === "bad" || level === "warn";
    return `ck-title text-[13px] ${issue ? "font-semibold text-zinc-950 dark:text-white" : "font-medium text-zinc-800 dark:text-zinc-200"}`;
  }
  function setCheckDrawer(row, open) {
    const dr = row && $(".ck-drawer", row);
    if (!dr) return;
    dr.hidden = !open;
    row.dataset.open = open ? "1" : "";
    const how = $(".ck-howto", row);
    if (how) how.setAttribute("aria-expanded", open ? "true" : "false");
    const val = $(".ck-val", row);
    if (val && row.dataset.proto === "0") val.className = ckValClass(row.dataset.level || "info", open);
  }

  const SCEN_ICONS = {
    ai: `<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v3m0 12v3M3 12h3m12 0h3m-2.6-6.4-2.1 2.1M8.7 15.3l-2.1 2.1m0-12.8 2.1 2.1m6.6 6.6 2.1 2.1"/><circle cx="12" cy="12" r="3"/></svg>`,
    streaming: `<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="15" x="2" y="4" rx="2"/><polygon points="10 9 15 11.5 10 14 10 9"/></svg>`,
    social: `<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
    captcha: `<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>`,
    fintech: `<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/></svg>`,
    email: `<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>`
  };

  function buildInitialDOM() {
    // 1. 20-segment health bar
    const segBar = $("#segBar");
    if (segBar) {
      segBar.innerHTML = CORE_CHECKS.map(([id, title]) =>
        `<span data-seg="${esc(id)}" title="${esc(title)}" class="flex-1 h-full rounded-full bg-zinc-200 dark:bg-zinc-800 transition-colors"></span>`
      ).join("");
    }

    // 1b. 6 Business Scenario Compact Visual Meters
    const sg = $("#scenarioGrid");
    if (sg) {
      sg.innerHTML = SCENARIOS_META.map(([id, name, sub]) => `
        <div data-scen="${esc(id)}" class="rounded-xl ring-1 ring-zinc-950/[0.06] bg-zinc-50/75 p-3.5 flex flex-col justify-between gap-2.5 dark:bg-white/[0.025] dark:ring-white/[0.07]">
          <div class="flex flex-wrap items-center justify-between gap-x-1.5 gap-y-1">
            <span class="inline-flex items-center gap-1.5 min-w-0">
              <span class="sc-icon shrink-0 text-zinc-500 dark:text-zinc-400">${SCEN_ICONS[id] || ""}</span>
              <span class="text-xs font-semibold text-zinc-900 dark:text-zinc-100 whitespace-nowrap">${esc(name)}</span>
            </span>
            <span class="sc-badge inline-flex items-center py-0.5 px-1.5 rounded text-[10px] font-semibold shrink-0 bg-zinc-200/70 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">待确认</span>
          </div>
          <div>
            <div class="flex items-baseline justify-between gap-1 mb-1.5">
              <span class="sc-score font-mono text-xl font-bold tracking-tight tabular-nums leading-none text-zinc-400 dark:text-zinc-500">--%</span>
              <span class="text-[10.5px] text-zinc-400 dark:text-zinc-500 truncate max-w-[55%]" title="${esc(sub)}">${esc(sub.split("/")[0].trim())}</span>
            </div>
            <div class="h-1.5 w-full rounded-full bg-zinc-200/80 overflow-hidden dark:bg-zinc-800">
              <div class="sc-bar h-full rounded-full bg-zinc-400 transition-all duration-300" style="width: 12%"></div>
            </div>
            <p class="sc-reason mt-2 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">等待全量探针确认后计算…</p>
          </div>
        </div>
      `).join("");
    }
    if (externalQueryIp) {
      const inp = $("#ipQueryInput");
      if (inp) inp.value = externalQueryIp;
    }

    // 2. Route Split Matrix (2-column hairline grid)
    const rm = $("#routeMatrix");
    if (rm) {
      rm.innerHTML = ROUTES_META.map(([id, name, sub]) => `
        <div data-route="${esc(id)}" class="bg-white px-5 py-3.5 flex items-center justify-between gap-3 hover:bg-zinc-50/80 dark:bg-[#121418] dark:hover:bg-white/[0.025] transition">
          <div class="min-w-0">
            <div class="font-medium text-zinc-900 dark:text-zinc-100">${esc(name)}</div>
            <div class="mt-0.5 text-[11.5px] text-zinc-500 dark:text-zinc-400 truncate">${esc(sub)}</div>
          </div>
          <div class="text-right min-w-0 max-w-[56%]">
            <div class="rt-val maskable font-mono text-xs font-semibold text-zinc-600 dark:text-zinc-400 truncate">探测中…</div>
            <div class="rt-sub maskable mt-0.5 text-[11px] text-zinc-500 dark:text-zinc-400 truncate"></div>
          </div>
        </div>
      `).join("");
      $$("[data-route]", rm).forEach(el => { ROUTE_EL[el.dataset.route] = el; });
    }

    // 3. 20 Core Checks (2-column visual cards with left status stripe + A ≠ B diff badge) + 4 Protocol Mini-Cards
    const coreBox = $("#coreChecksList"), protoBox = $("#protoChecksList");
    if (coreBox) {
      coreBox.innerHTML = CORE_CHECKS.map(([id, title], idx) => `
        <div data-ck="${esc(id)}" data-idx="${idx}" data-proto="0" data-level="info" class="${ckCardClass("info", true)}">
          <div class="flex flex-col gap-1.5 sm:flex-row sm:items-start sm:justify-between sm:gap-2.5">
            <div class="flex items-start gap-2.5 min-w-0 flex-1">
              <span class="ck-badge mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full text-[10.5px] font-bold bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">…</span>
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center gap-x-1.5 gap-y-1">
                  <span class="ck-title text-[13px] font-semibold text-zinc-950 dark:text-zinc-100">${esc(title)}</span>
                  <span class="ck-diff inline-flex items-center gap-1 py-0.5 px-1.5 rounded font-mono text-[10.5px] font-medium bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">待核验</span>
                  <span class="ck-tag sr-only"></span>
                </div>
                <p class="${ckValClass("info", false)}">等待探针汇总…</p>
              </div>
            </div>
            <div class="ck-actions flex items-center gap-0.5 shrink-0 ps-[30px] sm:ps-0 -ms-2 sm:ms-0">
              <button type="button" data-retest="${esc(id)}" hidden class="ck-retest py-1 px-2 inline-flex items-center gap-1 rounded-md text-[11px] font-medium text-zinc-600 hover:bg-zinc-100 hover:text-zinc-950 disabled:opacity-60 dark:text-zinc-400 dark:hover:bg-white/[0.06] dark:hover:text-zinc-100 transition">
                <svg class="size-3 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.64-6.36L21 8"/><path d="M21 3v5h-5"/></svg>
                <span class="ck-retest-label">重测</span>
              </button>
              <button type="button" data-howto="${esc(id)}" aria-expanded="false" class="ck-howto py-1 px-2 inline-flex items-center gap-1 rounded-md text-[11px] font-medium text-zinc-600 hover:bg-zinc-100 hover:text-zinc-950 dark:text-zinc-400 dark:hover:bg-white/[0.06] dark:hover:text-zinc-100 transition">
                <span class="ck-howto-label">原理</span>
                <svg class="size-3 shrink-0 transition-transform duration-150 group-data-[open=1]:rotate-180" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
              </button>
            </div>
          </div>
          <div class="ck-drawer mt-2.5 pt-2.5 border-t border-zinc-950/[0.06] text-xs leading-relaxed text-zinc-700 space-y-1.5 cursor-auto dark:border-white/[0.07] dark:text-zinc-300" hidden></div>
        </div>
      `).join("");
    }
    if (protoBox) {
      protoBox.innerHTML = PROTO_CHECKS.map(([id, title]) => `
        <div data-ck="${esc(id)}" data-proto="1" class="ck-card rounded-xl ring-1 ring-zinc-950/[0.06] bg-zinc-50/75 px-3.5 py-3 flex flex-col justify-between gap-2 dark:bg-white/[0.025] dark:ring-white/[0.07]">
          <div class="flex items-center justify-between gap-2">
            <span class="inline-flex items-center gap-1.5 min-w-0">
              <span class="ck-badge inline-flex size-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">i</span>
              <span class="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">${esc(title.split(" (")[0])}</span>
            </span>
            <button type="button" data-howto="${esc(id)}" class="ck-howto text-[11px] font-medium text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white">原理</button>
          </div>
          <p class="ck-val maskable text-[11.5px] text-zinc-500 dark:text-zinc-400 line-clamp-2 leading-snug">检测中…</p>
          <div class="ck-drawer pt-2 border-t border-zinc-950/[0.06] text-[11.5px] leading-relaxed text-zinc-700 space-y-1 dark:border-white/[0.07] dark:text-zinc-300" hidden></div>
        </div>
      `).join("");
    }
    $$("[data-ck]").forEach(el => { CHECK_EL[el.dataset.ck] = el; });

    // 4. Category Tabs & 191 Sniffer Explorer Rows
    const tabsBox = $("#groupTabs");
    if (tabsBox) {
      const counts = {};
      for (const [, g] of SNIFFERS) counts[g] = (counts[g] || 0) + 1;
      const allTabs = [["all", "全部探针", SNIFFERS.length], ...GROUPS.map(([g, name]) => [g, name, counts[g] || 0])];
      tabsBox.innerHTML = allTabs.map(([g, name, cnt], idx) => `
        <button type="button" role="tab" data-gtab="${esc(g)}" aria-selected="${idx === 0 ? "true" : "false"}"
          class="gtab-btn shrink-0 py-1.5 px-3 inline-flex items-center gap-1.5 rounded-lg text-xs font-medium transition ${idx === 0
            ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-950"
            : "bg-zinc-100 text-zinc-600 hover:bg-zinc-200/80 dark:bg-zinc-800/80 dark:text-zinc-300 dark:hover:bg-zinc-700"}">
          <span>${esc(name)}</span>
          <span class="font-mono text-[11px] opacity-75">${cnt}</span>
        </button>
      `).join("");
    }

    const sc = $("#snifferContainer");
    if (sc) {
      sc.innerHTML = GROUPS.map(([gid, gtitle, gdesc]) => {
        const items = SNIFFERS.map((s, idx) => ({ s, idx: idx + 1 })).filter(x => x.s[1] === gid);
        return `
          <div data-gsec="${esc(gid)}" class="sniffer-group">
            <div class="px-6 py-2.5 bg-zinc-50/80 border-b border-zinc-950/[0.05] flex flex-wrap items-center justify-between gap-2 dark:bg-white/[0.02] dark:border-white/[0.06]">
              <div class="flex items-center gap-2">
                <span class="text-xs font-semibold text-zinc-800 dark:text-zinc-200">${esc(gtitle)}</span>
                <span class="text-[11px] font-mono text-zinc-500 dark:text-zinc-400">(${items.length} 项)</span>
              </div>
              <span class="text-[11.5px] text-zinc-500 dark:text-zinc-400">${esc(gdesc)}</span>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 divide-y divide-zinc-950/[0.05] md:divide-y-0 md:gap-px bg-zinc-950/[0.06] dark:divide-white/[0.06] dark:bg-white/[0.06]">
              ${items.map(({ s: [id, , title, mask, desc], idx }) => `
                <div data-probe="${esc(id)}" data-g="${esc(gid)}" data-why="${esc(desc)}"
                  class="probe-row bg-white dark:bg-[#121418] px-5 py-2.5 flex items-center justify-between gap-3 cursor-pointer hover:bg-zinc-50 dark:hover:bg-white/[0.03] transition">
                  <div class="flex items-center gap-2 min-w-0 shrink-0 max-w-[48%]">
                    <span class="font-mono text-[10.5px] text-zinc-500 dark:text-zinc-400 w-7 shrink-0">#${String(idx).padStart(3, "0")}</span>
                    <span class="text-xs font-medium text-zinc-700 dark:text-zinc-300 truncate">${esc(title)}</span>
                    <button type="button" data-tipbtn="${esc(id)}" class="tip-trigger shrink-0 inline-flex items-center justify-center size-4 rounded-full text-[10px] font-semibold bg-zinc-100 text-zinc-600 hover:bg-zinc-200 hover:text-zinc-950 dark:bg-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-700" aria-label="查看原理">?</button>
                  </div>
                  <div class="probe-val ${mask ? "maskable " : ""}font-mono text-xs text-right text-zinc-500 dark:text-zinc-400 truncate min-w-0 flex-1">检测中…</div>
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
    if (badge) badge.textContent = `${cnt}/${total}`;
    const bar = $("#topProgBar");
    if (bar) bar.style.width = `${Math.min(100, Math.max(5, Math.round((cnt / total) * 100)))}%`;
    const txt = $("#liveStatusText");
    if (txt && !R.finished) {
      txt.textContent = `正在扫描 ${cnt} / ${total} 项…`;
    }
    const sSub = $("#scoreSub");
    if (sSub && !R.finished) {
      sSub.textContent = `已采集 ${cnt} / ${total} 项 · 全部确认后加载最终评分…`;
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
          (opts.tone === "bad" ? "text-rose-600 font-semibold dark:text-rose-400"
            : opts.tone === "warn" ? "text-amber-700 font-semibold dark:text-amber-400"
            : opts.tone === "ok" ? "text-emerald-700 font-medium dark:text-emerald-400"
            : opts.na ? "text-zinc-500 dark:text-zinc-400"
            : "text-zinc-900 dark:text-zinc-100");
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
        tone === "bad" ? "text-rose-600 dark:text-rose-400"
          : tone === "warn" ? "text-amber-700 dark:text-amber-400"
          : tone === "ok" ? "text-emerald-700 dark:text-emerald-400"
          : "text-zinc-900 dark:text-zinc-100"
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
    const metaIp = cleanIp(meta.ip);
    const allowPrimaryFill = !!meta.isSelf || !!R.srvFailed;
    let changed = false;
    if (!R.ip && metaIp && allowPrimaryFill) {
      R.ip = metaIp;
      const ipVerStr = R.ip.includes(":") ? "IPv6" : "IPv4";
      setProbe("ip", `${R.ip} (${ipVerStr})`);
      changed = true;
    }
    const sameExit = !R.ip
      ? allowPrimaryFill
      : (!metaIp || metaIp === cleanIp(R.ip) || (netPrefix(metaIp) && netPrefix(metaIp) === netPrefix(R.ip)));
    if (!sameExit) return;

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
      const isMob = !isDc && (!!meta.mobile || isMobileIp({ org: R.org, isp: R.org, asFull: R.asn }));
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
        ispBadge.textContent = R.netKind === "relay" ? "iCloud代理" : isDc ? "机房 IDC" : R.netKind === "mobile" ? "蜂窝移动" : "原生家宽";
        ispBadge.className = "inline-flex items-center py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap shrink-0 " + (
          isDc ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
            : "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
        );
      }
      if (!R.exits) R.exits = {};
      if (!R.exits.ex_self || (cleanIp(R.exits.ex_self.ip) === cleanIp(R.ip) && !R.exits.ex_self.cc && R.ipCC)) {
        const lbl = [countryName(R.ipCC), R.ipCity, R.org].filter(Boolean).join(" · ");
        R.exits.ex_self = { ip: R.ip, cc: R.ipCC, label: lbl };
        setProbe("ex_self", `${R.ipCC ? flagEmoji(R.ipCC) + " " : ""}${R.ip}${lbl ? " · " + lbl : ""}`);
        setRouteRow("ex_self", `${R.ipCC ? flagEmoji(R.ipCC) + " " : ""}${R.ip}`, lbl, R.netKind === "dc" ? "warn" : "ok");
      }
      refreshWebrtcProbeRow();
      refreshExitSplitBadges();
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
      R.srvFailed = true;
      const onlySrv = ["ptr", "clock", "proto", "tcpfp", "ipquirk", "ja4t", "tunnel", "ja4", "ja3", "tlsext", "pqkex", "ech", "h2fp", "h2akamai",
       "h_ua", "h_lang", "h_chua", "h_plat", "h_arch", "h_enc", "h_sec", "h_dnt"];
      if (!R.ip) onlySrv.unshift("ip", "geo", "coords", "isp", "nettype", "tzip");
      onlySrv.forEach(k => setNA(k, "服务端探针请求超时"));
      return;
    }

    R.srv = data;
    R.srvFailed = false;
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
    const ip = cleanIp(data.clientIp || data.ip || g.ip || "");
    const cc = g.countryCode || (cleanIp(R.ip) === ip ? R.ipCC || "" : "");
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
    const isMob = !isDc && isMobileIp(g);
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

      const uaOsNow = R.dev?.os || "";
      const claimAppleNow = /^(macOS|iOS|iPadOS)$/.test(uaOsNow);
      const claimWinNow = uaOsNow === "Windows";
      const osMisNow =
        (fam === "windows" && !claimWinNow) ||
        (fam === "apple" && !claimAppleNow) ||
        (fam === "linux" && (claimAppleNow || claimWinNow));
      const cellularMtuOk = isCellularNativeLink(uaOsNow, osMisNow) && tcp.mtu >= 1360 && tcp.mtu <= 1476;
      const tunLabels = {
        ethernet: `标准以太网直连 (MTU ${tcp.mtu})`,
        pppoe: `PPPoE 光猫拨号宽带 (MTU ${tcp.mtu})`,
        wireguard: cellularMtuOk ? `蜂窝移动 4G/5G 原生承载封装 (MTU ${tcp.mtu})` : `疑似 WireGuard 隧道封装 (MTU ${tcp.mtu})`,
        ipsec_or_tun: cellularMtuOk ? `蜂窝移动 GTP / CLAT 原生封装 (MTU ${tcp.mtu})` : `疑似 IPsec / 代理 TUN 虚拟网卡 (MTU ${tcp.mtu})`,
        openvpn_or_tun: `疑似 OpenVPN / 跨境隧道封装 (MTU ${tcp.mtu})`,
        tunnel: cellularMtuOk ? `蜂窝移动承载链路封装 (MTU ${tcp.mtu})` : `非标准隧道 MTU ${tcp.mtu} (MSS ${tcp.mss})`,
        jumbo_cloud: `云服务器内网巨型帧 (MTU ${tcp.mtu})`
      };
      setProbe("tunnel", tunLabels[tun] || (tcp.mtu ? `MTU ${tcp.mtu} (MSS ${tcp.mss})` : "未携带 MSS"), {
        tone: tun && !["ethernet", "pppoe"].includes(tun) && !cellularMtuOk ? "warn" : (cellularMtuOk ? "ok" : "neutral")
      });

      // IP layer DF / IPID / ECN & TCP Timestamp clock Hz + stateless SYN-spoof check
      const dfTxt = tcp.df === true ? "DF=1(不分片)" : tcp.df === false ? "DF=0(允许分片·macOS/BSD特征)" : "DF=?";
      const ipidStep = (tcp.synIpId != null && tcp.helloIpId != null)
        ? (tcp.synIpId === 0 && tcp.helloIpId === 0 ? "IPID=0恒零(Linux/Apple特征)" : `IPID ${tcp.synIpId}→${tcp.helloIpId}`)
        : (tcp.synIpId != null ? `SYN IPID=${tcp.synIpId}` : "IPID=–");
      const hzTxt = tcp.tsHz != null
        ? `TS时钟≈${tcp.tsHz}Hz`
        : tcp.tsNote === "ts_stripped_by_middlebox"
        ? "TS被运营商网关剥离(5G/NAT常见)"
        : (tcp.synTsval != null ? `TSval=${tcp.synTsval}` : "无TS时间戳");
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

    // HTTP/2 Akamai raw frame fingerprint (SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header order)
    const h2 = data.packet?.http2;
    R.h2Mismatch = "";
    if (h2 && h2.h2Used) {
      R.h2Fp = h2;
      const cb = claimedBrowser();
      const fam = h2.clientFamily || "";
      let mismatch = "";
      if ((cb === "Chrome" || cb === "Edge" || cb === "Opera") && /^(firefox|webkit|go|curl|python)$/.test(fam)) {
        mismatch = `UA 自称 ${cb}，但 HTTP/2 原始帧指纹却是 ${h2.clientGuess} (${(h2.pseudoOrder || []).join(",")})`;
      } else if (cb === "Firefox" && /^(chromium|webkit|go|curl|python)$/.test(fam)) {
        mismatch = `UA 自称 Firefox，但 HTTP/2 原始帧指纹却是 ${h2.clientGuess} (${(h2.pseudoOrder || []).join(",")})`;
      } else if ((cb === "Safari" || cb === "iOSWebKit") && /^(chromium|firefox|go|curl|python)$/.test(fam)) {
        mismatch = `UA 自称 Safari/WebKit，但 HTTP/2 原始帧指纹却是 ${h2.clientGuess} (${(h2.pseudoOrder || []).join(",")})`;
      } else if (/^(go|curl|python)$/.test(fam)) {
        mismatch = `HTTP/2 帧暴露自动化网络库特征：${h2.clientGuess}`;
      }
      R.h2Mismatch = mismatch;
      setProbe("h2akamai", mismatch ? `协议穿帮：${mismatch}` : `${h2.clientGuess} · ${h2.akamai}`, {
        tone: mismatch ? "bad" : "ok",
        why: `Akamai H2 指纹: ${h2.akamai}\nMD5: ${h2.akamaiHash || "-"}\n伪头顺序: ${(h2.pseudoOrder || []).join(" → ")}`
      });
    } else if (h2 && h2.h2Used === false) {
      setProbe("h2akamai", `客户端未协商 HTTP/2 (ALPN=${h2.alpn || "http/1.1"})`, { tone: "warn" });
    } else {
      setNA("h2akamai", data.packet?.tlsBridgeActive ? "复用连接未捕获新 H2 首包（点击重新检测）" : "未挂载 TLS 桥（线上 HTTPS 自动采集）");
    }

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
      ispBadge.textContent = isRelay ? "iCloud代理" : isDc ? "机房 IDC" : isMob ? "蜂窝移动" : "原生家宽";
      ispBadge.className = "inline-flex items-center py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap shrink-0 " + (
        isDc ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
          : "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
      );
    }
    const selfLbl = [countryName(cc), g.city, org].filter(Boolean).join(" · ");
    if (!R.exits) R.exits = {};
    if (ip) {
      R.exits.ex_self = { ip, cc, label: selfLbl };
      setProbe("ex_self", `${cc ? flagEmoji(cc) + " " : ""}${ip}${selfLbl ? " · " + selfLbl : ""}`);
    }
    setRouteRow("ex_self", `${cc ? flagEmoji(cc) + " " : ""}${ip}`, selfLbl, isDc ? "warn" : "ok");
    refreshWebrtcProbeRow();
    refreshExitSplitBadges();

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
  const REP_PROBE_IDS = ["reality443", "portscan", "rep_score", "rep_votes", "rep_native", "rep_asn", "rep_lease", "rep_rpki", "rep_shodan", "rep_threat", "rep_dnsbl", "rep_cidr", "rep_neigh"];

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
        isSelf: true,
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
        pill.textContent = `信誉 ${p.score}·${p.grade}`;
        pill.className = "inline-flex items-center py-0.5 px-1.5 rounded-full text-[10px] font-mono font-semibold whitespace-nowrap shrink-0 " + (
          p.score >= 82 ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
            : p.score >= 58 ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
            : "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
        );
      }
      // Refine KPI 3 ISP badge if 8-source voting caught a fake-ISP or hosting node
      if ((v.hosting?.E >= 0.55 || inf.cls === "hosting" || ci.x4bDatacenter) && R.netKind === "isp") {
        R.netKind = "dc";
        setProbe("nettype", `多源投票识破机房/托管线路 (${Math.round((v.hosting?.E || 0.7) * 100)}% 置信)`, { tone: "bad" });
        const ispBadge = $("#ispTypeBadge");
        if (ispBadge) {
          ispBadge.textContent = inf.conflict ? "伪家宽" : "机房 IDC";
          ispBadge.className = "inline-flex items-center py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap shrink-0 bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300";
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

    // 1b) portscan: live proxy / VPN / remote-control port back-scan (self egress only)
    const pt = intel.ports || {};
    if (intel.isSelfEgress === false) {
      setNA("portscan", `${prefixTag}出于防滥用，端口回扫仅对访客自身出口执行`);
    } else if (!pt.probed) {
      setNA("portscan", pt.reason === "timeout" ? "端口回扫超时" : "服务端未启用主动回扫");
    } else if (pt.synProxyLikely) {
      setProbe("portscan", `${(pt.open || []).length}/${pt.scanned} 个端口同时“开放”：出口前置 SYN-Proxy / 防火墙 Tarpit，结论不可信`, { tone: "warn" });
    } else if (!(pt.open || []).length) {
      setProbe("portscan", `${pt.scanned} 个代理 / VPN / 远控 / 面板端口全部关闭或丢包（家宽 NAT 特征）`, { tone: "ok", why: `回扫耗时 ${pt.elapsedMs} ms` });
    } else {
      const lst = pt.open.map(o => `${o.port}/${o.svc}`).join("、");
      const hard = (pt.proxyOpen || []).length || (pt.vpnOpen || []).length;
      setProbe("portscan", `开放 ${lst}`, {
        tone: hard ? "bad" : "warn",
        why: pt.open.map(o => `${o.port} ${o.svc}${o.banner ? " · " + o.banner : ""}`).join("\n") + `\n回扫耗时 ${pt.elapsedMs} ms`
      });
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
        (p.score ?? 0) >= 82 ? "bg-emerald-600 text-white" : (p.score ?? 0) >= 58 ? "bg-amber-500 text-white" : "bg-rose-600 text-white"
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
    if (btn) { btn.disabled = false; btn.textContent = "查询"; }
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

    // Micro-burst coalescing & jitter probe (6 pulses spaced ~14ms apart)
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
        if (b < 5) await new Promise(r => setTimeout(r, 14));
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
          if (Math.abs(bRes[k].srvUs - bRes[k - 1].srvUs) < 850 && (bRes[k].sent - bRes[k - 1].sent) >= 8) {
            coalescedPairs++;
          }
        }
        R.muxBurst = {
          stdRtt: +stdRtt.toFixed(1),
          coalescedPairs,
          clientSpanMs: Math.round(clientSpanMs),
          srvSpanMs: +srvSpanMs.toFixed(1),
          sampleRtts: rtts.map(x => Math.round(x))
        };
        refreshMuxJitterProbe();
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
    const prevSelf = R.exits?.ex_self || null;
    R.exits = prevSelf ? { ex_self: prevSelf } : {};
    if (R.srv && R.ip) {
      const selfLbl = [countryName(R.ipCC), R.srv?.geo?.city, R.org].filter(Boolean).join(" · ");
      R.exits.ex_self = { ip: R.ip, cc: R.ipCC, label: selfLbl };
      setProbe("ex_self", `${R.ipCC ? flagEmoji(R.ipCC) + " " : ""}${R.ip}${selfLbl ? " · " + selfLbl : ""}`);
    } else if (!prevSelf) {
      setNA("ex_self", "等待主连接返回");
    }

    // Mainland China exit probe (parallel race/fallback: ipip.net + speedtest.cn so blocked proxies don't wait 14s serially)
    const pCn = (async () => {
      let ip = "", loc = "";
      const [j1, j2] = await Promise.all([
        getJSON("https://myip.ipip.net/json", 3800).catch(() => null),
        getJSON("https://forge.speedtest.cn/api/location/info", 3800).catch(() => null)
      ]);
      if (j1?.data?.ip) {
        ip = cleanIp(j1.data.ip);
        loc = (j1.data.location || []).filter(Boolean).join(" · ");
      } else if (j2?.ip) {
        ip = cleanIp(j2.ip);
        loc = [j2.country, j2.province, j2.city, j2.isp].filter(Boolean).join(" · ");
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

    // International GeoIP exit (parallel api.ip.sb + ipwho.is so Mainland 5G without VPN doesn't wait 13s serially)
    const pIntl = (async () => {
      const [j1, j2] = await Promise.all([
        getJSON("https://api.ip.sb/geoip", 4200).catch(() => null),
        getJSON("https://ipwho.is/", 4200).catch(() => null)
      ]);
      let j = j1?.ip ? j1 : null;
      if (!j && j2?.ip) {
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
      const intlIp = cleanIp(j?.ip);
      if (!intlIp) {
        setNA("ex_intl", "国际探针不可达");
        setRouteRow("ex_intl", "不可达", "");
        return;
      }
      const cc = j.country_code || "";
      const sub = [countryName(cc), j.city, j.organization || j.isp].filter(Boolean).join(" · ");
      R.exits.ex_intl = { ip: intlIp, cc, label: sub };
      setProbe("ex_intl", `${flagEmoji(cc)} ${intlIp} · ${sub}`);
      setRouteRow("ex_intl", `${flagEmoji(cc)} ${intlIp}`, sub, "ok");
      backfillExitMeta({
        ip: intlIp,
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
      const raw = await getText(url, 4200).catch(() => "");
      const kv = parseCfTrace(raw);
      const traceIp = cleanIp(kv.ip);
      if (!traceIp) {
        setNA(key, `${name} 边缘不可达或被拦截`);
        setRouteRow(key, "不可达 / 被阻断", name);
        return null;
      }
      kv.ip = traceIp;
      const cc = kv.loc || "";
      const relayNote = isAppleRelay(traceIp) && (!kv.warp || kv.warp === "off") && /^(iOS|iPadOS|macOS)$/.test(R.dev?.os || "") ? " · Safari 隐私中继" : "";
      const sub = `${countryName(cc)} · 边缘节点 ${kv.colo || "?"} · ${kv.http || "h2"}${relayNote}`;
      R.exits[key] = { ip: traceIp, cc, colo: kv.colo, http: kv.http, kex: kv.kex, sni: kv.sni, warp: kv.warp, gateway: kv.gateway, label: sub };
      setProbe(key, `${flagEmoji(cc)} ${traceIp} · ${sub}`);
      setRouteRow(key, `${flagEmoji(cc)} ${traceIp}`, sub, "ok");
      if (key === "ex_cf") {
        backfillExitMeta({ ip: traceIp, cc, source: "Cloudflare Trace 备援" });
      }
      return kv;
    };

    const pGpt = runTraceProbe("ex_gpt", "https://chatgpt.com/cdn-cgi/trace", "ChatGPT");
    const pClaude = runTraceProbe("ex_claude", "https://claude.ai/cdn-cgi/trace", "Claude");
    const pCf = runTraceProbe("ex_cf", "https://www.cloudflare.com/cdn-cgi/trace", "Cloudflare");

    // Dual-stack IPv4 vs IPv6 independent probe
    const pStack = (async () => {
      const [r4, r6] = await Promise.all([
        getText("https://ipv4.icanhazip.com", 3800).then(s => ({ ip: cleanIp(s) }), () => null),
        getText("https://ipv6.icanhazip.com", 3800).then(s => ({ ip: cleanIp(s) }), () => null)
      ]);
      const v4 = r4?.ip || "";
      const v6 = r6?.ip && r6.ip.includes(":") ? r6.ip : "";
      R.stack = { v4, v6 };
      setProbe("stack", `IPv4: ${v4 || "无"} · IPv6: ${v6 || "未启用/仅IPv4"}`);
      setRouteRow("stack", v4 && v6 ? "IPv4 + IPv6 双栈在线" : v4 ? "纯 IPv4 链路" : "纯 IPv6 链路", `v4: ${v4 || "–"} / v6: ${v6 || "无"}`, "ok");
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

    R.exitsDone = true;
    refreshExitSplitBadges();
  }

  function refreshExitSplitBadges() {
    if (!R.exitsDone) return;
    const sp = analyzeExitSplit();
    const isBad = sp.state === "cn-leak";
    const isWarn = sp.state === "multi-country" || sp.state === "multi-prefix" || sp.state === "dual-stack-mismatch";
    const badge = $("#splitSummaryBadge");
    if (badge) {
      badge.textContent = isBad
        ? "大陆分流漏底"
        : isWarn
        ? `分流到 ${sp.distinctCount} 个出口`
        : sp.dualStackAligned
        ? "同运营商双栈一致"
        : sp.cgnatAligned
        ? "同运营商 CGNAT 一致"
        : "全局单一出口";
      badge.className = "inline-flex items-center py-1 px-3 rounded-full text-xs font-medium " + (
        isBad
          ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
          : isWarn
          ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
          : "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
      );
    }
    const tabRt = $("#tabRoutesBadge");
    if (tabRt) {
      tabRt.textContent = isBad ? "分流漏底" : isWarn ? `${sp.distinctCount} 出口` : "单一出口";
      tabRt.className = "py-0.5 px-1.5 rounded-full font-mono text-[11px] " + (
        isBad
          ? "bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300"
          : isWarn
          ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300"
          : "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300"
      );
    }
    if (R.stack && (R.stack.v4 || R.stack.v6)) {
      const { v4, v6 } = R.stack;
      const v6Leak = v4 && v6 && R.ip && !isSameCarrierCandidate(v6) && !isSameCarrierCandidate(v4);
      setRouteRow(
        "stack",
        v4 && v6 ? "IPv4 + IPv6 双栈在线" : v4 ? "纯 IPv4 链路" : "纯 IPv6 链路",
        `v4: ${v4 || "–"} / v6: ${v6 || "无"}`,
        v6Leak ? "bad" : "ok"
      );
    }
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
      getJSON(`https://${randHex1}.edns.ip-api.com/json`, 4200).catch(() => null),
      getJSON(`https://${randHex2}.edns.ip-api.com/json`, 4200).catch(() => null)
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

  function refreshMuxJitterProbe() {
    const m = R.muxBurst;
    if (!m) return;
    const rawCoalesced = m.coalescedPairs >= 3 || (m.srvSpanMs < m.clientSpanMs * 0.35 && m.clientSpanMs >= 30);
    const isMux = isMuxTunnelSuspect(m);
    const note = isMux
      ? " (检出多路复用粘包合并特征)"
      : rawCoalesced
      ? " (无线空口时隙聚合，三维测距已排除代理隧道)"
      : "";
    setProbe("muxjitter", `RTT 抖动 σ=${m.stdRtt.toFixed(1)}ms · 发射跨度 ${m.clientSpanMs}ms → 服务端到达跨度 ${m.srvSpanMs.toFixed(1)}ms${note}`, {
      tone: isMux ? "warn" : "ok",
      why: `6 脉冲同帧到达对(<0.85ms): ${m.coalescedPairs} 对 · 单次脉冲 RTT: ${(m.sampleRtts || []).map(x => x + "ms").join(", ")}`
    });
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
      const anycastCloserOnly = delta <= -65 && R.srvTcpRtt != null && (R.httpRtt - R.srvTcpRtt) < 42 && !getLeakedWebrtcIps().length;
      const suspect = Math.abs(delta) >= 95 && !anycastCloserOnly;
      setProbe("udprtt", `STUN UDP 候选 ${R.stunRttMs} ms vs HTTP TCP ${R.httpRtt} ms (差值 ${sign} ms)`, {
        tone: suspect ? "warn" : "ok",
        why: anycastCloserOnly
          ? "STUN Anycast 边缘节点物理距离比本站单播源站更近，且服务端 TCP 握手往返吻合、无异网 IP 泄漏。"
          : delta <= -65
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
          const ipMatch = c.match(/(?:\b|(?:candidate:\S+\s+\d+\s+\S+\s+\d+\s+))((?:\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F:]{3,39}\]?)(?:\b|\s|$)/);
          const rawAddr = ev.candidate.address || (ipMatch && ipMatch[1]) || "";
          if (!rawAddr || String(rawAddr).endsWith(".local")) return;
          const addr = cleanIp(rawAddr);
          if (!addr) return;
          const isSrflx = /\btyp\s+(?:srflx|prflx|relay)\b/i.test(c) || /^(?:srflx|prflx|relay)$/i.test(ev.candidate.type || "");
          if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fc[0-9a-f]{0,2}:|fd[0-9a-f]{0,2}:|fe[89ab][0-9a-f]?:)/i.test(addr)) {
            lanItems.add(addr);
          } else if (/^(0\.0\.0\.0|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|192\.0\.0\.|198\.1[89]\.|::1?$|2001:0?db8:)/i.test(addr)) {
            return;
          } else {
            if (isSrflx && firstSrflxMs == null) firstSrflxMs = Math.max(1, Math.round(performance.now() - tStart));
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
    } else if (!R.ip) {
      setProbe("webrtc", `${pubList.join(" · ")} (等待主出口归属核验…)`, { tone: "neutral" });
    } else {
      refreshWebrtcProbeRow();
    }
    updateUdpRttProbe();

    const realLan = lanList.filter(x => !x.endsWith(".local"));
    setProbe("lan", realLan.length ? `暴露真实局域网 IP: ${realLan.join(", ")}` : lanList.length ? `已由 mDNS 隐藏 (${lanList[0]})` : "未暴露局域网候选", {
      tone: realLan.length ? "warn" : "ok"
    });
  }

  function refreshWebrtcProbeRow() {
    if (!R.rtcDone || R.rtc === "off") return;
    const pubList = Array.isArray(R.rtc) ? R.rtc : [];
    if (!pubList.length) {
      setProbe("webrtc", "安全（未暴露公网 STUN 候选地址）", { tone: "ok" });
      return;
    }
    if (!R.ip) return;
    const leaked = getLeakedWebrtcIps();
    const directSame = pubList.every(x => cleanIp(x) === cleanIp(R.ip) || netPrefix(x) === netPrefix(R.ip));
    const lkCC = leaked.length ? candidateCC(leaked[0]) : "";
    const suffix = leaked.length
      ? (R.ipCC === "CN" && lkCC && lkCC !== "CN"
        ? ` (分流至 ${lkCC} 代理，与当前 CN 直连不符！)`
        : " (与当前代理出口不符！)")
      : directSame
      ? " (与出口一致)"
      : " (同国同运营商双栈/CGNAT，未跨网泄漏)";
    setProbe("webrtc", pubList.join(" · ") + suffix, {
      tone: leaked.length ? "bad" : "ok"
    });
  }

  async function reconcileCandidateIpMeta() {
    R.ipMeta = R.ipMeta || {};
    const candidates = new Set();
    const selfIp = cleanIp(R.ip);
    const addIfUnfamiliar = ip => {
      if (!ip || typeof ip !== "string") return;
      const clean = cleanIp(ip);
      if (!clean || clean === selfIp) return;
      if (selfIp && netPrefix(clean) && netPrefix(clean) === netPrefix(selfIp)) return;
      if (!R.ipMeta[clean]) candidates.add(clean);
    };
    if (Array.isArray(R.rtc)) R.rtc.forEach(addIfUnfamiliar);
    if (R.stack?.v4) addIfUnfamiliar(R.stack.v4);
    if (R.stack?.v6) addIfUnfamiliar(R.stack.v6);
    for (const v of Object.values(R.exits || {})) {
      if (v?.ip) addIfUnfamiliar(v.ip);
    }
    const batch = Array.from(candidates).slice(0, 8);
    if (batch.length) {
      const res = await getJSON(`./api/who/ip-meta?ips=${encodeURIComponent(batch.join(","))}`, 2800, "omit").catch(() => null);
      if (res?.ok && res.items && typeof res.items === "object") {
        for (const [k, val] of Object.entries(res.items)) {
          const ck = cleanIp(k);
          if (ck) R.ipMeta[ck] = val;
          R.ipMeta[k] = val;
        }
      }
    }
    refreshWebrtcProbeRow();
    refreshExitSplitBadges();
  }

  // 6. IPv6 EUI-64 Hardware MAC Leak Check (1 item: v6mac)
  function probeV6Mac() {
    const v6Pool = [R.ip, R.stack?.v6, ...(Array.isArray(R.rtc) ? R.rtc : []), ...Object.values(R.exits || {}).map(x => x?.ip)]
      .map(cleanIp)
      .filter(x => x && x.includes(":"));
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
    for (let i = 0; i < 120000; i++) {
      const cur = performance.now();
      if (cur > last) {
        minStep = Math.min(minStep, cur - last);
        last = cur;
        if (i >= 15000) break;
      }
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
      const timerResMs = Number.isFinite(minStep) ? minStep : 100;
      let acc = 1.000001;
      if (timerResMs >= 5) {
        for (let k = 0; k < 24000; k++) acc = (acc * 1.0000003 + 0.0000007) % 1024;
        R.cpuBench = { simdOk, p50Ms: +timerResMs.toFixed(3), p98Ms: +timerResMs.toFixed(3), stealRatio: 1, timerQuantized: true, sink: acc };
        setProbe("cpubench", `WASM SIMD ${simdOk ? "支持" : "不支持"} · 隐私粗化时钟 (${+timerResMs.toFixed(1)}ms 步长，跳过微秒抢占比对)`, {
          tone: "ok",
          why: `performance.now() 最小步长为 ${+timerResMs.toFixed(2)}ms，属浏览器防指纹降精度保护`
        });
      } else {
        const targetSliceMs = timerResMs >= 0.4 ? 3.2 : 0.85;
        let iters = 36000;
        const calStart = performance.now();
        while (iters < 1400000 && (performance.now() - calStart) < 18) {
          const tCal = performance.now();
          for (let k = 0; k < iters; k++) acc = (acc * 1.0000003 + 0.0000007) % 1024;
          const dtCal = performance.now() - tCal;
          if (dtCal >= targetSliceMs * 0.85) {
            if (dtCal < targetSliceMs) iters = Math.min(1400000, Math.ceil(iters * (targetSliceMs / dtCal)));
            break;
          }
          iters = Math.min(1400000, dtCal > 0 ? Math.ceil(iters * Math.min(8, (targetSliceMs / dtCal) * 1.15)) : iters * 4);
        }
        const slices = [];
        let zeroCnt = 0;
        const benchStart = performance.now();
        for (let s = 0; s < 28; s++) {
          const t0 = performance.now();
          for (let k = 0; k < iters; k++) {
            acc = (acc * 1.0000003 + 0.0000007) % 1024;
          }
          const rawDt = performance.now() - t0;
          if (rawDt <= 0) zeroCnt++;
          slices.push(rawDt);
          if (s >= 11 && (performance.now() - benchStart) >= 85) break;
        }
        const sorted = slices.slice().sort((a, b) => a - b);
        const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
        const p98 = sorted[Math.floor(sorted.length * 0.98)] || 0;
        const timerQuantized = zeroCnt > 0 || p50 < Math.max(0.15, timerResMs * 1.8);
        const stealRatio = timerQuantized ? 1 : +(p98 / Math.max(p50, 0.1)).toFixed(2);
        R.cpuBench = { simdOk, p50Ms: +p50.toFixed(3), p98Ms: +p98.toFixed(3), stealRatio, timerQuantized, sink: acc };
        setProbe(
          "cpubench",
          timerQuantized
            ? `WASM SIMD ${simdOk ? "支持" : "不支持"} · WebKit/隐私量化时钟 (${+timerResMs.toFixed(2)}ms 步长，物理端侧正常)`
            : `WASM SIMD ${simdOk ? "支持" : "不支持"} · 单片中位 ${p50.toFixed(2)}ms · 抢占抖动比 p98/p50=${stealRatio}x`,
          {
            tone: stealRatio >= 5.5 ? "warn" : "ok",
            why: `${slices.length} 组自适应时间片 (iters=${iters}) p50=${p50.toFixed(3)}ms, p98=${p98.toFixed(3)}ms, 时钟步长=${+timerResMs.toFixed(4)}ms（超售云主机或虚拟机发生 Hypervisor VM-Exit 时尾延迟显著放大）`
          }
        );
      }
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
        visitEl.textContent = "清存储仍被 ETag 认出";
        visitEl.className = "mt-0.5 text-[11.5px] text-rose-600 dark:text-rose-400 font-semibold truncate";
      } else if (R.traceSurvived?.length) {
        visitEl.textContent = `${R.traceSurvived.length}/4 项存储认出回访`;
        visitEl.className = "mt-0.5 text-[11.5px] text-amber-700 dark:text-amber-400 font-medium truncate";
      } else {
        visitEl.textContent = "新访客 · 隔离良好";
        visitEl.className = "mt-0.5 text-[11.5px] text-emerald-700 dark:text-emerald-400 truncate";
      }
    }
  }

  function haversineKm(lat1, lon1, lat2, lon2) {
    const rad = d => (d * Math.PI) / 180;
    const h = Math.sin(rad(lat2 - lat1) / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(rad(lon2 - lon1) / 2) ** 2;
    return 12742 * Math.asin(Math.sqrt(h));
  }

  /* ---------- v7.4 Extended Probes (14 items): portscan · rttgeo · proxyhdr · h_lfmt · tzdst · clocksrc · mqscreen · mobilex · wasmfeat · fontlocal · cdp · winchrome · incog · input ---------- */

  // (1) CDP / DevTools Runtime attach side effect + injected evaluation frames + Selenium DOM markers
  async function probeCdp() {
    let hit = false;
    const marks = [];
    // 现代 V8：Runtime 域启用时，inspector 会为控制台中的 Error 生成描述并调用 Error.prepareStackTrace（未附着时不会）
    const prevPrep = Error.prepareStackTrace;
    try {
      Error.prepareStackTrace = (e, frames) => { hit = true; return typeof prevPrep === "function" ? prevPrep(e, frames) : `${e}`; };
      console.debug(new Error("whoprobe-cdp"));
    } catch (e) {} finally {
      Error.prepareStackTrace = prevPrep;
    }
    // 旧版 V8：预览 Error 时读取 stack 访问器
    try {
      const err = new Error("whoprobe-cdp");
      Object.defineProperty(err, "stack", { configurable: false, enumerable: false, get() { hit = true; return ""; } });
      console.debug(err);
    } catch (e) {}
    await new Promise(r => setTimeout(r, 40));
    try {
      const st = String(new Error().stack || "");
      if (/__puppeteer_evaluation_script__|pptr:/i.test(st)) marks.push("Puppeteer 注入帧");
      if (/__playwright_evaluation_script__/i.test(st)) marks.push("Playwright 注入帧");
    } catch (e) {}
    try {
      const de = document.documentElement;
      if (["webdriver", "selenium", "driver"].some(a => de.getAttribute(a) != null)) marks.push("Selenium DOM 标记");
      if (window.domAutomation || window.domAutomationController) marks.push("domAutomation 控制器");
      if (window.__nightmare) marks.push("Nightmare");
    } catch (e) {}
    try {
      if (window.Notification && navigator.permissions?.query) {
        const st = await within(navigator.permissions.query({ name: "notifications" }), 800, null);
        if (st && Notification.permission === "denied" && st.state === "prompt") marks.push("Notification 与 Permissions 状态矛盾（无头 Chrome）");
      }
    } catch (e) {}
    R.cdpHit = hit;
    R.cdpMarks = marks;
    if (marks.length) R.botHits = Array.from(new Set([...(R.botHits || []), ...marks]));
    setProbe("cdp", marks.length
      ? `检出自动化注入：${marks.join(" · ")}${hit ? " · CDP Runtime 已附着" : ""}`
      : hit
      ? "检测到 CDP Runtime 序列化副作用（开发者工具已打开，或被 Puppeteer / Playwright 控制）"
      : "未见 CDP Runtime 序列化副作用、注入帧与 Selenium 标记",
    { tone: marks.length ? "bad" : hit ? "warn" : "ok" });
  }

  // (2) Window chrome (outer vs inner): headless zero frame & docked DevTools, excluding zoom / fullscreen / PWA
  function probeWinChrome() {
    const ow = window.outerWidth || 0, oh = window.outerHeight || 0, iw = window.innerWidth || 0, ih = window.innerHeight || 0;
    const dx = ow - iw, dy = oh - ih;
    const touchOnly = mq("(pointer: coarse)") && !mq("(any-pointer: fine)");
    const fullscreen = !!document.fullscreenElement || mq("(display-mode: fullscreen)") || (Math.abs(iw - screen.width) <= 1 && Math.abs(ih - screen.height) <= 1);
    const app = mq("(display-mode: standalone)") || mq("(display-mode: minimal-ui)") || mq("(display-mode: window-controls-overlay)");
    const ratio = iw ? ow / iw : 1;
    const zoomed = Math.abs(ratio - 1) > 0.02 && [0.25, 0.33, 0.5, 0.67, 0.75, 0.8, 0.9, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4, 5].some(z => Math.abs(ratio - z) < 0.015);
    const flags = [];
    let headless = false;
    if (!ow || !oh) {
      headless = true;
      flags.push("outerWidth / outerHeight = 0（旧版无头 Chrome）");
    } else if (!touchOnly && !fullscreen && !app && dx === 0 && dy === 0) {
      headless = true;
      flags.push("浏览器外框高度 0（无工具栏 / 标签栏：Kiosk、新版无头或自动化窗口）");
    }
    if (ow > screen.width + 16 && oh > screen.height + 16) {
      headless = true;
      flags.push(`窗口 ${ow}×${oh} 在宽高两个维度上都大于屏幕 ${screen.width}×${screen.height}（虚拟屏幕 / 无头默认尺寸）`);
    }
    const devtools = !zoomed && !touchOnly && !headless && (dx > 260 || dy > 300);
    R.winHeadless = headless;
    R.winDevtools = devtools;
    const base = `外框 ${ow}×${oh} · 视口 ${iw}×${ih} · UI 占用 宽 ${dx}px / 高 ${dy}px${zoomed ? ` · 页面缩放≈${Math.round(ratio * 100)}%` : ""}${fullscreen ? " · 全屏" : ""}`;
    setProbe("winchrome", flags.length ? `${flags.join("；")} · ${base}` : devtools ? `疑似开发者工具停靠 · ${base}` : base, {
      tone: headless ? "warn" : devtools ? "warn" : "neutral"
    });
  }

  // (3) CSS media queries vs JS screen readings (binary-searched device-width/height, resolution, orientation)
  function mqMaxPx(feature, hi = 16384) {
    if (!mq(`(min-${feature}: 1px)`)) return null;
    let lo = 1;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (mq(`(min-${feature}: ${mid}px)`)) lo = mid; else hi = mid - 1;
    }
    return lo;
  }
  function probeMqScreen() {
    const W = screen.width, H = screen.height, dpr = window.devicePixelRatio || 1;
    const diffs = [], okParts = [];
    const cssW = mqMaxPx("device-width"), cssH = mqMaxPx("device-height");
    if (cssW != null && cssH != null) {
      if (Math.abs(cssW - W) > 1 || Math.abs(cssH - H) > 1) diffs.push(`JS screen ${W}×${H} ≠ CSS device ${cssW}×${cssH}`);
      else okParts.push(`device ${cssW}×${cssH}`);
    }
    const lo = Math.max(0.01, dpr - 0.02).toFixed(3), hi = (dpr + 0.02).toFixed(3);
    if (mq("(min-resolution: 0.001dppx)")) {
      if (!mq(`(min-resolution: ${lo}dppx) and (max-resolution: ${hi}dppx)`)) diffs.push(`devicePixelRatio=${dpr} 与 CSS resolution 不符`);
      else okParts.push(`${+dpr.toFixed(3)}dppx`);
    } else if (mq("(-webkit-min-device-pixel-ratio: 0.001)")) {
      if (!mq(`(-webkit-min-device-pixel-ratio: ${lo}) and (-webkit-max-device-pixel-ratio: ${hi})`)) diffs.push(`devicePixelRatio=${dpr} 与 -webkit-device-pixel-ratio 不符`);
      else okParts.push(`${+dpr.toFixed(3)}x`);
    }
    if (Math.abs(window.innerWidth - window.innerHeight) > 40) {
      const cssPortrait = mq("(orientation: portrait)");
      const jsPortrait = window.innerHeight >= window.innerWidth;
      if (cssPortrait !== jsPortrait) diffs.push(`视口 ${window.innerWidth}×${window.innerHeight} 与 CSS orientation 方向相反`);
      else okParts.push(jsPortrait ? "竖屏" : "横屏");
    }
    R.mqDiffs = navigator.brave ? [] : diffs;
    setProbe("mqscreen", diffs.length ? `交叉矛盾：${diffs.join("；")}` : `一致 · ${okParts.join(" · ") || "媒体查询与 JS 读数吻合"}`, {
      tone: diffs.length ? (navigator.brave ? "warn" : "bad") : "ok"
    });
  }

  // (4) DST & historical offsets: Date.getTimezoneOffset vs Intl IANA rules at 5 instants
  function probeTzDst() {
    const tz = R.tz || "";
    if (!tz) return setNA("tzdst");
    let fmt;
    try {
      fmt = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric" });
    } catch (e) { return setNA("tzdst", "Intl 不支持该时区 ID"); }
    const intlOff = ts => {
      const p = {};
      for (const x of fmt.formatToParts(new Date(ts))) p[x.type] = x.value;
      return Math.round((Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - ts) / 60000);
    };
    const y = new Date().getFullYear();
    const pts = [[Date.UTC(y, 0, 15, 12), `${y}-01`], [Date.UTC(y, 6, 15, 12), `${y}-07`], [Date.UTC(2015, 0, 15, 12), "2015-01"], [Date.UTC(2015, 6, 15, 12), "2015-07"], [Date.UTC(2005, 6, 15, 12), "2005-07"]];
    const bad = [];
    let offs;
    try {
      offs = pts.map(([ts, lbl]) => {
        const a = intlOff(ts), b = -new Date(ts).getTimezoneOffset();
        if (a !== b) bad.push(`${lbl} Intl UTC${fmtUtcOffset(a)} ≠ Date UTC${fmtUtcOffset(b)}`);
        return a;
      });
    } catch (e) { return setNA("tzdst"); }
    const dst = offs[0] !== offs[1];
    R.tzDstMismatch = bad.length ? bad : null;
    setProbe("tzdst", bad.length
      ? `规则断裂：${bad.slice(0, 2).join("；")}${bad.length > 2 ? ` 等 ${bad.length} 处` : ""}`
      : `${tz} · 冬 UTC${fmtUtcOffset(offs[0])} / 夏 UTC${fmtUtcOffset(offs[1])}${dst ? " · 有夏令时" : " · 无夏令时"} · ${pts.length}/${pts.length} 时点一致`,
    { tone: bad.length ? "bad" : "ok", why: pts.map(([, lbl], i) => `${lbl}: UTC${fmtUtcOffset(offs[i])}`).join("\n") });
  }

  // (5) Clock source consistency (Date APIs vs each other, vs monotonic clock, vs server)
  function probeClockSrc() {
    const s = [];
    for (let i = 0; i < 5; i++) {
      const a = Date.now(), b = new Date().getTime(), c = Date.parse(new Date().toISOString());
      s.push(Math.max(Math.abs(a - b), Math.abs(a - c)));
    }
    const internalGap = Math.min(...s);
    R.clockInternalGap = internalGap;
    let monoTxt = "";
    if (performance.timeOrigin && performance.now() < 15 * 60 * 1000) {
      const ds = [];
      for (let i = 0; i < 5; i++) ds.push(Date.now() - (performance.timeOrigin + performance.now()));
      ds.sort((x, y) => x - y);
      const drift = Math.round(ds[2]);
      R.clockMonoDrift = drift;
      monoTxt = ` · 单调时钟偏差 ${drift >= 0 ? "+" : ""}${drift} ms${Math.abs(drift) >= 2000 ? "（系统休眠或时钟被改）" : ""}`;
    }
    const srvTxt = R.clockSkewMs != null ? ` · 较服务端 ${R.clockSkewMs >= 0 ? "+" : ""}${R.clockSkewMs} ms` : "";
    setProbe("clocksrc", internalGap > 1000
      ? `Date 接口相互矛盾 (${internalGap} ms)：Date.now / new Date / Date.parse 被部分 Hook${monoTxt}${srvTxt}`
      : `Date.now / new Date / Date.parse 一致${monoTxt}${srvTxt}`,
    { tone: internalGap > 1000 ? "bad" : "ok" });
  }

  // (6) WebAssembly proposal matrix → minimum engine generation
  const WASM_FEATS = [
    ["simd", "SIMD", [0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253, 15, 253, 98, 11]],
    ["exceptions", "异常处理", [0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 10, 8, 1, 6, 0, 6, 64, 25, 11, 11]],
    ["tailCall", "尾调用", [0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 10, 6, 1, 4, 0, 18, 0, 11]],
    ["gc", "GC 结构体", [0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 95, 1, 120, 0]],
    ["relaxedSimd", "Relaxed SIMD", [0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 15, 1, 13, 0, 65, 1, 253, 15, 65, 2, 253, 15, 253, 128, 2, 11]],
    ["extendedConst", "扩展常量", [0, 97, 115, 109, 1, 0, 0, 0, 5, 3, 1, 0, 1, 11, 9, 1, 0, 65, 1, 65, 2, 106, 11, 0]],
    ["threads", "线程原子", [0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 5, 4, 1, 3, 1, 1, 10, 11, 1, 9, 0, 65, 0, 254, 16, 2, 0, 26, 11]],
    ["bulk", "批量内存", [0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 5, 3, 1, 0, 1, 10, 14, 1, 12, 0, 65, 0, 65, 0, 65, 0, 252, 10, 0, 0, 11]],
    ["refTypes", "引用类型", [0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 10, 7, 1, 5, 0, 208, 112, 26, 11]],
    ["multiValue", "多返回值", [0, 97, 115, 109, 1, 0, 0, 0, 1, 6, 1, 96, 0, 2, 127, 127, 3, 2, 1, 0, 10, 8, 1, 6, 0, 65, 0, 65, 0, 11]],
    ["signExt", "符号扩展", [0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 10, 8, 1, 6, 0, 65, 0, 192, 26, 11]],
    ["satConv", "饱和转换", [0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 10, 12, 1, 10, 0, 67, 0, 0, 0, 0, 252, 0, 26, 11]],
    ["mutableGlobals", "可变全局", [0, 97, 115, 109, 1, 0, 0, 0, 2, 8, 1, 1, 97, 1, 98, 3, 127, 1, 6, 6, 1, 127, 1, 65, 0, 11]]
  ];
  function probeWasmFeatures() {
    if (typeof WebAssembly !== "object" || typeof WebAssembly.validate !== "function") {
      R.wasmFeat = null;
      return setNA("wasmfeat", "WebAssembly 已禁用（JIT-less / 锁定模式 / 企业策略）");
    }
    const res = {};
    for (const [k, , bytes] of WASM_FEATS) {
      try { res[k] = WebAssembly.validate(new Uint8Array(bytes)); } catch (e) { res[k] = false; }
    }
    res.jspi = "Suspending" in WebAssembly;
    R.wasmFeat = res;
    let floor = 0, fam = "";
    if (R.engine === "V8") {
      fam = "Chromium";
      floor = res.jspi ? 137 : res.gc ? 119 : res.relaxedSimd ? 114 : res.tailCall ? 112 : res.exceptions ? 95 : res.simd ? 91 : 0;
    } else if (R.engine === "SpiderMonkey") {
      fam = "Firefox";
      floor = res.tailCall ? 121 : res.gc ? 120 : res.exceptions ? 100 : res.simd ? 89 : 0;
    }
    R.wasmFloor = floor;
    const on = WASM_FEATS.filter(([k]) => res[k]).length;
    const missing = WASM_FEATS.filter(([k]) => !res[k]).map(([, n]) => n);
    setProbe("wasmfeat", `${on}/${WASM_FEATS.length} 项提案${res.jspi ? " + JSPI" : ""}${floor ? ` · 推算内核 ≥ ${fam} ${floor}` : ""}${missing.length ? ` · 缺 ${missing.slice(0, 3).join(" / ")}${missing.length > 3 ? "…" : ""}` : ""}`, {
      why: WASM_FEATS.map(([k, n]) => `${res[k] ? "✓" : "✗"} ${n}`).join("\n") + `\n${res.jspi ? "✓" : "✗"} JSPI (WebAssembly.Suspending)`
    });
  }

  // (7) FontFace local() side-channel vs Canvas measureText font list
  const LOCAL_FONT_PROBES = [
    ["Segoe UI", "win", ["Segoe UI", "SegoeUI"]],
    ["Calibri", "win", ["Calibri"]],
    ["Consolas", "win", ["Consolas"]],
    ["Microsoft YaHei", "win", ["Microsoft YaHei", "MicrosoftYaHei", "微软雅黑"]],
    ["SimSun", "win", ["SimSun", "宋体"]],
    ["Yu Gothic", "win", ["Yu Gothic Regular", "YuGothic-Regular", "Yu Gothic"]],
    ["Malgun Gothic", "win", ["Malgun Gothic", "MalgunGothic"]],
    ["Helvetica Neue", "apple", ["Helvetica Neue", "HelveticaNeue"]],
    ["Menlo", "apple", ["Menlo Regular", "Menlo-Regular", "Menlo"]],
    ["PingFang SC", "apple", ["PingFang SC Regular", "PingFangSC-Regular", "PingFang SC"]],
    ["Hiragino Sans", "apple", ["Hiragino Sans W3", "HiraginoSans-W3"]],
    ["Songti SC", "apple", ["Songti SC Regular", "STSongti-SC-Regular"]],
    ["DejaVu Sans", "linux", ["DejaVu Sans", "DejaVuSans"]],
    ["Liberation Sans", "linux", ["Liberation Sans", "LiberationSans"]],
    ["Ubuntu", "linux", ["Ubuntu Regular", "Ubuntu-Regular", "Ubuntu"]],
    ["Noto Sans CJK SC", "linux", ["Noto Sans CJK SC Regular", "NotoSansCJKsc-Regular", "Noto Sans CJK SC"]],
    ["Roboto", "android", ["Roboto", "Roboto Regular", "Roboto-Regular"]]
  ];
  async function probeFontLocal() {
    if (typeof FontFace !== "function") return setNA("fontlocal", "当前环境不支持 CSS Font Loading API");
    let seq = 0;
    const tryName = name => within(
      new FontFace(`wp-local-${++seq}`, `local("${String(name).replace(/["\\]/g, "")}")`).load().then(() => true, () => false),
      1500, false
    );
    const results = await Promise.all(LOCAL_FONT_PROBES.map(async ([fam, os, names]) => {
      for (const n of names) {
        if (await tryName(n)) return [fam, os, true];
      }
      return [fam, os, false];
    }));
    const found = results.filter(r => r[2]);
    R.localFonts = found.map(r => r[0]);
    const usable = found.length >= 2;
    const canvasSet = new Set(R.fonts || []);
    const hidden = usable && !navigator.brave ? found.filter(r => PROBE_FONTS.includes(r[0]) && !canvasSet.has(r[0])).map(r => r[0]) : [];
    const phantom = usable ? results.filter(r => !r[2] && canvasSet.has(r[0])).map(r => r[0]) : [];
    const osHas = k => found.some(r => r[1] === k);
    const os = R.dev?.os || "";
    let osConflict = "";
    if (usable) {
      if (os === "macOS" && !osHas("apple")) osConflict = "自报 macOS 却缺少 Menlo / Helvetica Neue / PingFang 等系统必备字体";
      else if (os === "Windows" && !osHas("win")) osConflict = "自报 Windows 却缺少 Segoe UI / Calibri / Consolas 等系统必备字体";
    }
    R.fontLocalHidden = hidden.length >= 2 ? hidden : [];
    R.fontLocalOsConflict = osConflict;
    const issues = [];
    if (osConflict) issues.push(osConflict);
    if (hidden.length >= 2) issues.push(`local() 证明已安装 ${hidden.slice(0, 3).join(" / ")}，Canvas 探测却报告不存在（measureText 被 Hook）`);
    else if (phantom.length >= 2) issues.push(`Canvas 报告存在 ${phantom.slice(0, 3).join(" / ")}，local() 却加载失败`);
    setProbe("fontlocal", !usable
      ? `local() 仅命中 ${found.length}/${LOCAL_FONT_PROBES.length} 款（浏览器限制本地字体访问，跳过交叉比对）`
      : issues.length
      ? `${issues.join("；")}`
      : `local() 命中 ${found.length}/${LOCAL_FONT_PROBES.length} 款，与 Canvas 字体探测及 ${os || "当前系统"} 一致`,
    { tone: osConflict || hidden.length >= 2 ? "bad" : issues.length ? "warn" : usable ? "ok" : "neutral", why: `local() 命中: ${R.localFonts.join(", ") || "无"}` });
  }

  // (8) Private / incognito window detection (engine-specific storage side channels)
  async function probeIncognito() {
    let verdict = null, how = "";
    try {
      if (R.engine === "V8") {
        const heapLim = performance.memory?.jsHeapSizeLimit || 1073741824;
        let quota = null;
        if (navigator.webkitTemporaryStorage?.queryUsageAndQuota) {
          quota = await within(new Promise(res => navigator.webkitTemporaryStorage.queryUsageAndQuota((u, q) => res(q), () => res(null))), 1500, null);
        }
        if (!quota && navigator.storage?.estimate) quota = (await within(navigator.storage.estimate(), 1500, null))?.quota || null;
        if (quota) {
          verdict = quota < heapLim * 2;
          how = `站点配额 ${Math.round(quota / 1048576)} MB vs 阈值 ${Math.round(heapLim * 2 / 1048576)} MB`;
        }
      } else if (R.engine === "JavaScriptCore" || R.engine === "SpiderMonkey") {
        if (navigator.storage?.getDirectory) {
          const r = await within(navigator.storage.getDirectory().then(() => ({ ok: true }), e => ({ ok: false, e })), 1500, null);
          if (r) {
            const msg = `${r.e?.name || ""} ${r.e?.message || ""}`;
            verdict = r.ok ? false : R.engine === "JavaScriptCore" ? /unknown transient reason/i.test(msg) : /security/i.test(msg);
            how = "OPFS getDirectory";
          }
        } else if (R.engine === "SpiderMonkey") {
          verdict = navigator.serviceWorker === undefined;
          how = "serviceWorker 可用性";
        }
      }
    } catch (e) {}
    R.incognito = verdict;
    if (verdict == null) return setNA("incog", "当前内核无可靠无痕侧信道");
    setProbe("incog", verdict ? `检测为无痕 / 隐私浏览窗口 (${how})` : `常规持久化窗口 (${how})`, { tone: verdict ? "warn" : "neutral" });
  }

  // (9) Mobile emulation consistency (claimed phone / tablet vs touch, pointer, hover, GPU, screen)
  function probeMobileConsistency() {
    const ua = navigator.userAgent || "";
    const os = R.dev?.os || "";
    const claimPhone = /iPhone|iPod/.test(ua) || (/Android|HarmonyOS/.test(ua) && /Mobile/.test(ua));
    const claimTablet = !claimPhone && (/iPad/.test(ua) || /Android/.test(ua));
    const tp = navigator.maxTouchPoints || 0;
    const coarse = mq("(pointer: coarse)"), anyFine = mq("(any-pointer: fine)"), hover = mq("(hover: hover)");
    const touchEvt = "ontouchstart" in window;
    const gpu = String(R.gpuClean || R.gpuRaw || "");
    const desktopGpu = /NVIDIA|GeForce|Quadro|Radeon|Intel\(R\)|Intel Iris|Iris\(TM\)|UHD Graphics|Apple M\d|SwiftShader|llvmpipe|Direct3D/i.test(gpu);
    const mobileGpu = /Adreno|Mali|PowerVR|Xclipse|Immortalis|Apple GPU|Maleoon/i.test(gpu);
    if (!claimPhone && !claimTablet) {
      R.mobileHits = [];
      const label = os === "macOS" && tp > 1
        ? `UA 为 macOS 且具备 ${tp} 点触控：iPadOS 桌面版网站模式（正常）`
        : tp > 0 && coarse && !anyFine
        ? `桌面 UA + 纯触屏 (${tp} 点)：二合一平板模式`
        : `桌面环境 · 触控点 ${tp} · ${coarse ? "粗指针" : "精细指针"}${hover ? " · 可悬停" : ""}`;
      return setProbe("mobilex", label, { tone: "neutral" });
    }
    const hits = [];
    if (tp === 0) hits.push("maxTouchPoints=0");
    if (!touchEvt) hits.push("无 ontouchstart 触摸事件");
    if (claimPhone && !coarse && anyFine) hits.push("主指针为精细鼠标");
    if (claimPhone && hover && !coarse) hits.push("支持悬停 (hover)");
    if (/Android|HarmonyOS/.test(ua) && desktopGpu && !mobileGpu) hits.push(`桌面显卡 ${gpu.slice(0, 36)}`);
    if (/iPhone|iPad|iPod/.test(ua) && gpu && !/Apple/i.test(gpu)) hits.push(`非 Apple 显卡 ${gpu.slice(0, 36)}`);
    if (claimPhone && Math.min(screen.width, screen.height) > 700) hits.push(`屏幕短边 ${Math.min(screen.width, screen.height)}px 远超手机`);
    R.mobileHits = hits;
    const who = claimPhone ? "手机" : "平板";
    setProbe("mobilex", hits.length
      ? `自称${who}，但 ${hits.join(" · ")}`
      : `自称${who}：触控 ${tp} 点 / ${coarse ? "粗指针" : "精细指针"} / 触摸事件 / ${mobileGpu ? "移动 GPU" : "GPU 未暴露"} 全部自洽`,
    { tone: hits.length >= 2 ? "bad" : hits.length ? "warn" : "ok" });
  }

  // (10) Input-event trust & mechanical straight-line ratio (passively recorded during the scan)
  function inputStraightRatio(pts) {
    let wins = 0, straight = 0;
    for (let i = 0; i + 8 < pts.length; i += 4) {
      const a = pts[i], b = pts[i + 8];
      const len = Math.hypot(b.x - a.x, b.y - a.y);
      if (len < 40) continue;
      wins++;
      let maxDev = 0;
      for (let j = i + 1; j < i + 8; j++) {
        const p = pts[j];
        maxDev = Math.max(maxDev, Math.abs((b.x - a.x) * (a.y - p.y) - (a.x - p.x) * (b.y - a.y)) / len);
      }
      if (maxDev < 1.0) straight++;
    }
    return wins >= 10 ? straight / wins : null;
  }
  function probeInputTrust() {
    const L = INPUT_LOG;
    const total = L.moves + L.keys + L.clicks + L.touches + L.wheels;
    R.inputUntrusted = L.untrusted;
    const ratio = inputStraightRatio(L.pts);
    R.inputStraight = ratio;
    if (!total && !L.untrusted) return setProbe("input", "检测期间未发生鼠标 / 键盘 / 触摸交互（正常，可移动鼠标后点「重新检测」）", { na: true });
    const parts = [`鼠标移动 ${L.moves}`, `点击 ${L.clicks}`, `按键 ${L.keys}`, `触摸 ${L.touches}`, `滚轮 ${L.wheels}`].filter(s => !/ 0$/.test(s));
    const flags = [];
    if (L.untrusted) flags.push(`${L.untrusted} 个 isTrusted=false 合成事件`);
    R.inputCdpCoord = L.cdpCoord >= 3 && L.cdpCoord / Math.max(1, L.ptrEvents) > 0.8 ? L.cdpCoord : 0;
    if (R.inputCdpCoord) flags.push(`${L.cdpCoord}/${L.ptrEvents} 个鼠标事件 screenX/Y = pageX/Y（CDP 派发特征）`);
    if (ratio != null && ratio >= 0.9) flags.push(`轨迹 ${Math.round(ratio * 100)}% 为机械直线`);
    if (L.moves >= 30 && L.zeroMove / L.moves > 0.9) flags.push("movementX/Y 恒为 0");
    setProbe("input", flags.length ? `${flags.join(" · ")} · ${parts.join(" / ")}` : `${parts.join(" / ")} · 全部为可信原生事件${ratio != null ? ` · 直线段 ${Math.round(ratio * 100)}%` : ""}`, {
      tone: L.untrusted || R.inputCdpCoord ? "bad" : flags.length ? "warn" : "ok"
    });
  }

  // (11) Global multi-region RTT triangulation with speed-of-light floor (AWS DynamoDB /ping endpoints)
  const RTT_REGIONS = [
    ["us-east-1", "美东弗吉尼亚", "US", 38.9, -77.4], ["us-west-1", "美西加州", "US", 37.4, -121.9], ["us-west-2", "美西俄勒冈", "US", 45.8, -119.7],
    ["ca-central-1", "加拿大蒙特利尔", "CA", 45.5, -73.6], ["sa-east-1", "巴西圣保罗", "BR", -23.5, -46.6], ["eu-west-1", "爱尔兰都柏林", "IE", 53.3, -6.3],
    ["eu-west-2", "英国伦敦", "GB", 51.5, -0.1], ["eu-central-1", "德国法兰克福", "DE", 50.1, 8.7], ["eu-north-1", "瑞典斯德哥尔摩", "SE", 59.3, 18.1],
    ["me-central-1", "阿联酋", "AE", 25.2, 55.3], ["ap-south-1", "印度孟买", "IN", 19.1, 72.9], ["ap-southeast-1", "新加坡", "SG", 1.35, 103.8],
    ["ap-southeast-2", "澳洲悉尼", "AU", -33.9, 151.2], ["ap-northeast-1", "日本东京", "JP", 35.7, 139.7], ["ap-northeast-2", "韩国首尔", "KR", 37.6, 127.0],
    ["ap-east-1", "中国香港", "HK", 22.3, 114.2], ["af-south-1", "南非开普敦", "ZA", -33.9, 18.4], ["cn-north-1", "中国北京", "CN", 39.9, 116.4]
  ];
  async function probeRttGeo() {
    const urlOf = id => id.startsWith("cn-") ? `https://dynamodb.${id}.amazonaws.com.cn/ping` : `https://dynamodb.${id}.amazonaws.com/ping`;
    const once = async u => {
      const t = performance.now();
      try {
        await fetch(u, { mode: "no-cors", cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(3000) });
        return performance.now() - t;
      } catch (e) { return null; }
    };
    const measure = async u => {
      if (await once(u) == null) return null; // cold: DNS + TCP + TLS
      const warm = [await once(u), await once(u)].filter(x => x != null);
      return warm.length ? Math.round(Math.min(...warm)) : null;
    };
    const queue = RTT_REGIONS.slice();
    const results = [];
    const worker = async () => {
      while (queue.length) {
        const [id, name, cc, lat, lon] = queue.shift();
        const ms = await measure(urlOf(id));
        if (ms != null) results.push({ id, name, cc, lat, lon, ms });
      }
    };
    await within(Promise.all(Array.from({ length: 6 }, worker)), 12000, null);
    results.sort((a, b) => a.ms - b.ms);
    R.rttGeo = results;
    refreshRttGeoProbe();
  }
  function analyzeRttGeo() {
    const list = R.rttGeo || [];
    if (!list.length) return null;
    let violation = null;
    if (R.ipLat != null && R.ipLon != null && Number.isFinite(R.ipLat) && Number.isFinite(R.ipLon)) {
      for (const r of list) {
        const km = haversineKm(R.ipLat, R.ipLon, r.lat, r.lon);
        // 光纤往返物理下限 ≈ 距离 / 100 ms（单程 200 km/ms），预先扣除 800 km 的 IP 库定位误差
        const floorMs = Math.max(0, (km - 800) / 100);
        if (km >= 2000 && r.ms + 8 < floorMs && (!violation || floorMs - r.ms > violation.floorMs - violation.ms)) {
          violation = { ...r, km: Math.round(km), floorMs: Math.round(floorMs) };
        }
      }
    }
    return { best: list[0], violation, count: list.length };
  }
  function refreshRttGeoProbe() {
    if (!R.rttGeo) return;
    const a = analyzeRttGeo();
    if (!a) return setNA("rttgeo", "全球测距端点均不可达（网络策略拦截）");
    const top = R.rttGeo.slice(0, 3).map(r => `${r.name} ${r.ms}ms`).join(" · ");
    const why = R.rttGeo.map(r => `${r.name} (${r.id}): ${r.ms} ms`).join("\n");
    if (a.violation) {
      const v = a.violation;
      setProbe("rttgeo", `光速违例：${v.name} 往返仅 ${v.ms}ms，但出口登记地距其 ${v.km.toLocaleString()} km（物理下限≈${v.floorMs}ms） · 最近 ${top}`, { tone: "bad", why });
    } else {
      setProbe("rttgeo", `最近 ${top}（${a.count} 区域可达）`, { why });
    }
  }

  // (12) Server-observed proxy forwarding headers + Accept-Language q-value grammar
  function probeHeaderForensics() {
    const srv = R.srv;
    if (!srv || !srv.headers) {
      setNA("proxyhdr", "服务端观测接口未返回");
      setNA("h_lfmt", "服务端观测接口未返回");
      return;
    }
    const ph = srv.proxyHeaders;
    if (!ph) {
      setNA("proxyhdr", "服务端版本未提供代理头分析");
    } else {
      const parts = [];
      if ((ph.names || []).length) parts.push(`携带 ${ph.names.join(", ")}`);
      if (ph.xffHops > 0) parts.push(`X-Forwarded-For 预置 ${ph.xffHops} 跳上游`);
      if (ph.via) parts.push(`Via: ${ph.via}`);
      R.proxyHdrHits = parts;
      setProbe("proxyhdr", parts.length ? `检出中间层转发头：${parts.join(" · ")}` : "未携带 Via / Forwarded / X-Forwarded-For 等代理转发头", { tone: parts.length ? "bad" : "ok" });
    }
    const al = String(srv.headers["accept-language"] || "");
    if (!al) {
      R.alIssues = [];
      return setNA("h_lfmt", "未发送 Accept-Language");
    }
    const toks = al.split(",").map(s => s.trim()).filter(Boolean).map(s => {
      const [tag, ...ps] = s.split(";").map(x => x.trim());
      const qp = ps.find(p => /^q=/i.test(p));
      return { tag: (tag || "").toLowerCase(), q: qp ? Number(qp.slice(2)) : 1, qRaw: qp ? qp.slice(2) : null };
    });
    const issues = [];
    for (let i = 1; i < toks.length; i++) {
      if (toks[i].q > toks[i - 1].q + 1e-9) { issues.push("q 权重未递减"); break; }
    }
    if (toks.some(t => !(t.q > 0 && t.q <= 1) || (t.qRaw != null && !/^(0(\.\d{1,3})?|1(\.0{1,3})?)$/.test(t.qRaw)))) issues.push("q 值格式非法");
    const navPrim = new Set((R.langs || []).map(l => String(l).toLowerCase().split("-")[0]));
    const alien = toks.filter(t => t.tag && t.tag !== "*" && !navPrim.has(t.tag.split("-")[0])).map(t => t.tag);
    if (alien.length && navPrim.size) issues.push(`含 JS 语言列表之外的语种 (${alien.slice(0, 3).join(", ")})`);
    const reduced = toks.length === 1 && (R.langs || []).length > 1;
    R.alIssues = issues;
    setProbe("h_lfmt", issues.length
      ? `格式异常：${issues.join("；")}`
      : `${toks.length} 项 · q 权重递减合规 · 语种与 navigator.languages 吻合${reduced ? " · 仅发送首选语言（精简策略）" : ""}`,
    { tone: issues.length ? "bad" : "ok" });
  }

  /* ---------- v7.5 Big-Vendor Anti-Bot Probes (12 items): autokeys · jsenv · headless · stealth · focus · cpuarch · sysfont · navprops · tzname · chgrease · aigeo · audiolat
     参考：TikTok webmssdk、Akamai sensor_data、PerimeterX/HUMAN、DataDome、Cloudflare 挑战脚本，以及 GitHub 开源
     fingerprintjs/BotD、fingerprintjs (sources)、abrahamjuliot/CreepJS、bot.sannysoft.com、rebrowser-bot-detector、brotector ---------- */

  const nativeFnRe = /\{\s*\[native code\]\s*\}\s*$/;
  const isNativeFn = fn => { try { return typeof fn === "function" && nativeFnRe.test(Function.prototype.toString.call(fn)); } catch (e) { return false; } };
  const claimedBrowser = () => {
    const ua = navigator.userAgent || "";
    if (/Edg\//.test(ua)) return "Edge";
    if (/OPR\//.test(ua)) return "Opera";
    if (/Firefox\//.test(ua) && !/Seamonkey/i.test(ua)) return "Firefox";
    if (/CriOS|FxiOS|EdgiOS/.test(ua)) return "iOSWebKit";
    if (/Chrome\//.test(ua) || /Chromium\//.test(ua)) return "Chrome";
    if (/Safari\//.test(ua) && /Version\//.test(ua)) return "Safari";
    return "";
  };
  const chromeMajor = () => +((/Chrom(?:e|ium)\/(\d+)/.exec(navigator.userAgent) || [])[1] || 0);

  // (1) Automation / crawler framework global markers (BotD distinctiveProperties + PerimeterX/Akamai/TikTok key lists)
  const AUTO_WINDOW_KEYS = [
    ["Selenium", ["_Selenium_IDE_Recorder", "_selenium", "calledSelenium", "callSelenium", "__selenium_evaluate", "__selenium_unwrapped", "__webdriver_script_fn", "__webdriver_script_func", "__webdriver_evaluate", "__webdriver_unwrapped", "__driver_evaluate", "__driver_unwrapped", "__fxdriver_evaluate", "__fxdriver_unwrapped", "__webdriverFunc", "_WEBDRIVER_ELEM_CACHE", "ChromeDriverw", "webdriver", "_webdriver"]],
    ["Watir", ["__lastWatirAlert", "__lastWatirConfirm", "__lastWatirPrompt"]],
    ["PhantomJS", ["callPhantom", "_phantom"]],
    ["Phantomas", ["__phantomas"]],
    ["Nightmare", ["__nightmare", "nightmare"]],
    ["Cypress", ["Cypress", "__cypress"]],
    ["TestCafe", ["%hammerhead%", "%testCafeDriverInstance%"]],
    ["WebdriverIO", ["wdioElectron"]],
    ["Playwright", ["__playwright", "__pwInitScripts", "__playwright__binding__", "__pwWebSocketDispatch"]],
    ["Puppeteer", ["__puppeteer_evaluation_script__", "__puppeteer_utility_world__"]],
    ["CEF", ["RunPerfTest"]],
    ["CefSharp", ["CefSharp", "cefSharp"]],
    ["Awesomium", ["awesomium"]],
    ["FMiner", ["fmget_targets"]],
    ["Geb", ["geb"]],
    ["Spynner", ["spynner_additional_js_loaded"]],
    ["domAutomation", ["domAutomation", "domAutomationController"]]
  ];
  const AUTO_WEAK_KEYS = [["CoachJS", "emit"], ["Rhino", "spawn"]];
  const AUTO_DOC_KEYS = ["__webdriver_evaluate", "__selenium_evaluate", "selenium-evaluate", "__webdriver_script_function", "__webdriver_script_func", "__webdriver_script_fn", "__fxdriver_evaluate", "__driver_unwrapped", "__webdriver_unwrapped", "__driver_evaluate", "__selenium_unwrapped", "__fxdriver_unwrapped", "$chrome_asyncScriptInfo", "__$webdriverAsyncExecutor", "$cdc_asdjflasutopfhvcZLmcf", "$cdc_asdjflasutopfhvcZLmcfl_"];
  function probeAutoKeys() {
    const hits = [], weak = [];
    const has = k => { try { return k in window; } catch (e) { return false; } };
    for (const [fw, keys] of AUTO_WINDOW_KEYS) {
      const found = keys.filter(has);
      if (found.length) hits.push(`${fw}(${found.slice(0, 2).join(",")})`);
    }
    for (const [fw, k] of AUTO_WEAK_KEYS) if (has(k)) weak.push(`${fw}?(${k})`);
    try {
      const docHit = AUTO_DOC_KEYS.filter(k => k in document);
      if (docHit.length) hits.push(`document.${docHit[0]}`);
      const winKeys = Object.getOwnPropertyNames(window);
      const cdc = winKeys.find(k => /^([a-z]){3}_.*_(Array|Promise|Symbol)$/.test(k) || /^\$?cdc_[a-z0-9]/i.test(k));
      if (cdc) hits.push(`ChromeDriver 注入变量 (${cdc.slice(0, 18)}…)`);
      const docCdc = Object.getOwnPropertyNames(document).find(k => /^\$?cdc_|^\$wdc_/.test(k));
      if (docCdc) hits.push("document.$cdc_ 标记");
      // CDP Runtime.addBinding 会在 window 上留下空函数名的原生函数
      const anonNative = winKeys.filter(k => { try { const v = window[k]; return typeof v === "function" && v.name === "" && isNativeFn(v); } catch (e) { return false; } });
      if (anonNative.length) weak.push(`CDP addBinding?(${anonNative.slice(0, 2).join(",")})`);
    } catch (e) {}
    if (/PhantomJS|Headless|Electron|slimerjs/i.test(navigator.appVersion || "")) hits.push("appVersion 含 PhantomJS / Headless / Electron / SlimerJS");
    if (typeof Function.prototype.bind !== "function") hits.push("缺少 Function.prototype.bind（PhantomJS）");
    try { null[0](); } catch (e) { if (/PhantomJS/i.test(String(e && e.stack))) hits.push("错误栈含 PhantomJS"); }
    try {
      // rebrowser：主文档被 CDP Fetch.fulfillRequest / Playwright route.fulfill 拦截改写
      const nav = performance.getEntriesByType("navigation")[0];
      if (nav && nav.nextHopProtocol === "" && nav.transferSize > 0 && nav.deliveryType === "" && nav.workerStart === 0) hits.push("主文档响应被自动化框架拦截改写 (fulfillRequest)");
    } catch (e) {}
    try { if (/Sequentum/i.test(String(window.external))) hits.push("Sequentum (window.external)"); } catch (e) {}
    try {
      // Puppeteer exposeFunction / Playwright exposeBinding：页面上出现非原生且带绑定特征的全局函数
      const binds = Object.getOwnPropertyNames(window).filter(k => {
        try {
          const v = window[k];
          return typeof v === "function" && !isNativeFn(v) && /__puppeteer|exposeBinding|__playwright|binding\(|callBinding/i.test(Function.prototype.toString.call(v).slice(0, 400));
        } catch (e) { return false; }
      });
      if (binds.length) hits.push(`exposeFunction 绑定 (${binds.slice(0, 2).join(",")})`);
    } catch (e) {}
    R.autoKeyHits = hits;
    if (hits.length) R.botHits = Array.from(new Set([...(R.botHits || []), ...hits]));
    setProbe("autokeys", hits.length
      ? `检出 ${hits.length} 类自动化 / 爬虫框架标记：${hits.slice(0, 4).join(" · ")}`
      : weak.length ? `未见强特征，存在通用全局名 ${weak.join(" · ")}（可能为页面脚本）` : `扫描 ${AUTO_WINDOW_KEYS.reduce((n, [, k]) => n + k.length, 0) + AUTO_DOC_KEYS.length} 个框架标记与 ChromeDriver 变量，全部未命中`,
    { tone: hits.length ? "bad" : weak.length ? "warn" : "ok", why: "覆盖 Selenium / ChromeDriver / Watir / PhantomJS / Phantomas / Nightmare / Cypress / TestCafe / WebdriverIO / Playwright / Puppeteer / CEF / CefSharp / Awesomium / FMiner / Geb / Spynner / Sequentum 等 BotD、PerimeterX、Akamai 与 TikTok 风控脚本同款清单。" });
  }

  // (2) Host JS environment: Node / Electron / jsdom / NW.js / Tauri / App WebView bridges
  function probeJsEnv() {
    const bad = [], info = [];
    try {
      const p = window.process;
      if (p && typeof p === "object") {
        if (p.versions?.electron || p.type === "renderer") bad.push(`Electron ${p.versions?.electron || "渲染进程"}`);
        else if (p.versions?.node) bad.push(`Node.js ${p.versions.node}`);
      }
    } catch (e) {}
    try { if (typeof window.Buffer === "function" && window.Buffer.from) bad.push("Node Buffer 全局"); } catch (e) {}
    try { if (typeof window.require === "function" && typeof window.module === "object") bad.push("CommonJS require/module"); } catch (e) {}
    try { if (window.global === window && typeof window.process === "object") bad.push("Node global 别名"); } catch (e) {}
    if (/jsdom/i.test(navigator.userAgent)) bad.push("jsdom UA");
    if (/Electron\//.test(navigator.userAgent)) bad.push("Electron UA");
    if (typeof window.nw === "object") bad.push("NW.js");
    if (window.__TAURI__ || window.__TAURI_INTERNALS__) info.push("Tauri 桌面壳");
    if (window.webkit?.messageHandlers) info.push("iOS WKWebView 原生桥");
    if (window.ReactNativeWebView) info.push("React Native WebView");
    if (window.flutter_inappwebview) info.push("Flutter InAppWebView");
    if (window.AndroidBridge || window.JSBridge || window.WeixinJSBridge || window.__wxjs_environment) info.push("App 内置 WebView 桥 (微信/JSBridge)");
    R.jsEnvBad = bad;
    setProbe("jsenv", bad.length
      ? `页面运行在非浏览器宿主：${bad.join(" · ")}`
      : info.length ? `应用内容器：${info.join(" · ")}` : "标准浏览器运行时（未见 Node / Electron / jsdom / NW.js 注入）",
    { tone: bad.length ? "bad" : info.length ? "warn" : "ok" });
  }

  // (3) Headless rendering & environment signals (CreepJS headless / Sannysoft / BotD)
  async function probeHeadless() {
    const hits = [], soft = [];
    const ua = navigator.userAgent || "";
    const desktop = !/Android|iPhone|iPad|iPod|Mobile/i.test(ua);
    const isChromium = R.engine === "V8";
    try {
      const d = document.createElement("div");
      d.style.cssText = "position:absolute;left:-9999px;top:0;width:4px;height:4px;background-color:ActiveText";
      document.body.appendChild(d);
      const bg = getComputedStyle(d).backgroundColor;
      d.remove();
      R.activeTextColor = bg;
    } catch (e) {}
    try {
      const img = document.createElement("img");
      img.style.cssText = "position:absolute;left:-9999px;top:0";
      const done = new Promise(r => { img.onerror = () => r(true); img.onload = () => r(false); });
      img.src = "data:image/png;base64,d2hvcHJvYmU=";
      document.body.appendChild(img);
      const errored = await within(done, 1500, null);
      const w = img.width, h = img.height;
      img.remove();
      R.brokenImg = errored ? `${w}×${h}` : null;
      if (errored && isChromium && w === 0 && h === 0) hits.push("破损图片尺寸 0×0（有界面 Chrome 为 16×16 图标）");
    } catch (e) {}
    try {
      const brands = (navigator.userAgentData?.brands || []).map(b => b.brand).join(",");
      if (/Headless/i.test(brands)) hits.push("userAgentData 品牌含 HeadlessChrome");
    } catch (e) {}
    if (!navigator.languages || navigator.languages.length === 0) hits.push("navigator.languages 为空");
    if (isChromium && desktop) {
      const pl = navigator.plugins?.length ?? -1;
      if (navigator.pdfViewerEnabled === true && pl === 0) hits.push("pdfViewerEnabled=true 但 plugins 为空");
      if (navigator.pdfViewerEnabled === false && pl === 0) soft.push("PDF 查看器与插件全部缺失（无头或企业策略）");
      if (navigator.connection && navigator.connection.rtt === 0) soft.push("connection.rtt = 0（无网络质量估算）");
      if (/^(macOS|Windows)$/.test(R.dev?.os || "") && Array.isArray(R.voices) && speechSynthesis?.getVoices?.().length === 0) soft.push("系统语音合成引擎 0 个语音");
    }
    const iw = window.innerWidth, ih = window.innerHeight;
    if (desktop && ((iw === 800 && ih === 600) || (iw === 1280 && ih === 720) || (iw === 1920 && ih === 1080 && window.outerHeight === ih))) {
      soft.push(`视口恰为自动化框架默认尺寸 ${iw}×${ih}`);
    }
    if (R.gpuSoft) hits.push("WebGL 为 SwiftShader / llvmpipe 软件渲染");
    try {
      if (/Mesa OffScreen/i.test(R.gpuRaw || "")) hits.push("WebGL 渲染器 Mesa OffScreen（无头特征）");
    } catch (e) {}
    // ActiveText：Chromium 仅在 Windows 把它映射为系统超链接色，其余平台恒为默认纯红；自报 Windows 却是纯红 → 非真实 Windows
    if (isChromium && R.dev?.os === "Windows" && R.activeTextColor === "rgb(255, 0, 0)" && !mq("(prefers-color-scheme: dark)")) {
      soft.push("自报 Windows（浅色模式）但 ActiveText 为 Chromium 默认纯红");
    }
    // brotector：Worker 内 getHighEntropyValues 全空 → CDP setUserAgentOverride 未携带 metadata
    if (isChromium && navigator.userAgentData?.getHighEntropyValues && typeof Worker === "function") {
      try {
        const src = "navigator.userAgentData&&navigator.userAgentData.getHighEntropyValues(['architecture','model','platformVersion','uaFullVersion','bitness']).then(v=>postMessage(v),()=>postMessage(null));if(!navigator.userAgentData)postMessage(null);";
        const url = URL.createObjectURL(new Blob([src], { type: "application/javascript" }));
        const wk = new Worker(url);
        const v = await within(new Promise(r => { wk.onmessage = e => r(e.data); wk.onerror = () => r(null); }), 1500, null);
        wk.terminate();
        URL.revokeObjectURL(url);
        if (v && ["architecture", "platformVersion", "uaFullVersion", "bitness"].every(k => !v[k]) && (R.hi?.platformVersion || R.hi?.uaFullVersion)) {
          hits.push("Worker 内高熵 Client Hints 全为空（CDP UA 覆写未带 metadata）");
        }
      } catch (e) {}
    }
    R.headlessHits = hits;
    R.headlessSoft = soft;
    if (hits.length) R.botHits = Array.from(new Set([...(R.botHits || []), ...hits.map(h => `无头:${h.split("（")[0]}`)]));
    setProbe("headless", hits.length
      ? `${hits.length} 项无头特征：${hits.join(" · ")}${soft.length ? ` · 另有 ${soft.length} 项弱信号` : ""}`
      : soft.length ? `弱信号：${soft.join(" · ")}` : `ActiveText ${R.activeTextColor || "-"} · 破损图 ${R.brokenImg || "-"} · 插件 ${navigator.plugins?.length ?? "-"} 个，未见无头渲染特征`,
    { tone: hits.length ? "bad" : soft.length ? "warn" : "ok" });
  }

  // (4) Stealth-patch residue (puppeteer-extra-plugin-stealth / undetected-chromedriver / anti-detect browsers)
  function probeStealth() {
    const hits = [];
    const cb = claimedBrowser();
    const isChromium = R.engine === "V8";
    const maj = chromeMajor();
    const ownSrc = (() => { try { return (/(https?:\/\/[^\s)]+?app\.js)/.exec(new Error().stack || "") || [])[1] || "app.js"; } catch (e) { return "app.js"; } })();
    if (isChromium && maj >= 89) {
      if (navigator.webdriver === undefined) hits.push("navigator.webdriver 为 undefined（原生应为 false，删除式补丁）");
      const wd = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
      if (!wd) hits.push("Navigator.prototype.webdriver 描述符被删除");
      else if (wd.get && !isNativeFn(wd.get)) hits.push("webdriver getter 非原生");
    }
    if (isChromium && (cb === "Chrome" || cb === "Edge" || cb === "Opera") && !/Android/.test(navigator.userAgent)) {
      if (!window.chrome) hits.push("自称 Chrome 却缺少 window.chrome");
      else {
        try {
          if (Object.getOwnPropertyNames(window).slice(-50).includes("chrome") && Object.keys(window).slice(-50).includes("chrome")) hits.push("window.chrome 位于全局属性末尾（事后注入）");
        } catch (e) {}
        for (const k of ["loadTimes", "csi"]) {
          const fn = window.chrome[k];
          if (typeof fn === "function" && !isNativeFn(fn)) hits.push(`chrome.${k} 为 JS 伪造函数`);
        }
        if (window.chrome.app && typeof window.chrome.app.getDetails === "function" && !isNativeFn(window.chrome.app.getDetails)) hits.push("chrome.app 为伪造对象");
      }
    }
    // srcdoc iframe：隐身补丁常把 contentWindow 代理回主窗口或遗漏 chrome 对象
    try {
      // CreepJS hasIframeProxy：未挂入 DOM 的 iframe 原生 contentWindow 必为 null，stealth 的 Proxy 会返回对象
      const loose = document.createElement("iframe");
      loose.srcdoc = "wp";
      if (loose.contentWindow) hits.push("未挂载 iframe 的 contentWindow 非 null（iframe.contentWindow 补丁）");
    } catch (e) {}
    try {
      const rt = window.chrome?.runtime;
      for (const k of ["sendMessage", "connect"]) {
        const fn = rt && rt[k];
        if (typeof fn !== "function") continue;
        let bad = Object.prototype.hasOwnProperty.call(fn, "prototype");
        try { new fn(); bad = true; } catch (e) { if (!(e instanceof TypeError)) bad = true; }
        if (bad) { hits.push(`chrome.runtime.${k} 为伪造函数（可被 new 或带 prototype）`); break; }
      }
    } catch (e) {}
    try {
      const f = document.createElement("iframe");
      f.srcdoc = "<!doctype html><title>wp</title>";
      f.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden";
      f.setAttribute("aria-hidden", "true");
      document.body.appendChild(f);
      const cw = f.contentWindow;
      if (cw === window) hits.push("srcdoc iframe.contentWindow 指向主窗口（Proxy 补丁）");
      else if (cw) {
        if (window.chrome && isChromium && !cw.chrome) hits.push("iframe 内 window.chrome 缺失");
        if (cw.navigator && navigator.webdriver !== cw.navigator.webdriver) hits.push("iframe 与主页面 webdriver 不一致");
        if (cw.navigator && navigator.plugins?.length !== cw.navigator.plugins?.length) hits.push("iframe 与主页面 plugins 数量不一致");
      }
      f.remove();
    } catch (e) {}
    // 原生 getter 非法调用的错误栈中出现 Proxy / Reflect / 扩展或注入脚本帧
    const stackSuspect = [];
    const probeStack = (label, get) => {
      if (typeof get !== "function") return;
      try { get.call(Object.create(null)); stackSuspect.push(`${label}(未抛错)`); } catch (e) {
        const st = String(e && e.stack || "");
        const lines = st.split("\n").slice(1).filter(l => !l.includes(ownSrc));
        if (lines.some(l => /Proxy|Object\.apply|Reflect\.apply|newHandler|chrome-extension:|moz-extension:|safari-web-extension:|pptr:|__puppeteer|__playwright|UtilityScript\.|evaluation_script/.test(l))) stackSuspect.push(label);
      }
    };
    for (const k of ["userAgent", "platform", "hardwareConcurrency", "deviceMemory", "languages", "webdriver", "plugins"]) {
      probeStack(`navigator.${k}`, Object.getOwnPropertyDescriptor(Navigator.prototype, k)?.get);
    }
    probeStack("WebGL.getParameter", window.WebGLRenderingContext?.prototype?.getParameter);
    probeStack("Canvas.toDataURL", window.HTMLCanvasElement?.prototype?.toDataURL);
    if (stackSuspect.length) hits.push(`原生接口错误栈含代理帧 (${stackSuspect.slice(0, 3).join(", ")})`);
    // PluginArray / MimeTypeArray 结构完整性（隐身补丁常用普通对象伪造）
    try {
      const pl = navigator.plugins, mt = navigator.mimeTypes;
      if (window.PluginArray && pl && !(pl instanceof PluginArray)) hits.push("navigator.plugins 不是 PluginArray 实例");
      if (pl && pl.length) {
        if (window.Plugin && !(pl[0] instanceof Plugin)) hits.push("plugins[0] 不是 Plugin 实例");
        if (pl.item(0) !== pl[0]) hits.push("plugins.item(0) 与下标访问不一致");
        if (mt && mt.length && mt[0].enabledPlugin && !Array.from(pl).includes(mt[0].enabledPlugin)) hits.push("mimeTypes.enabledPlugin 不指向 plugins 成员");
        // Chromium dom_plugin_array.cc：PDF 查看器可用时固定为 5 个内置 PDF 插件
        if (isChromium && !/Android/.test(navigator.userAgent) && navigator.pdfViewerEnabled) {
          const want = ["PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer", "Microsoft Edge PDF Viewer", "WebKit built-in PDF"];
          const names = Array.from(pl).map(p => p.name);
          if (names.length !== 5 || want.some(n => !names.includes(n))) hits.push(`插件名单非 Chromium 内置 PDF 五件套 (${names.slice(0, 3).join(", ") || "空"})`);
          if (mt && mt.length !== 2) hits.push(`mimeTypes 数量 ${mt.length}（应为 application/pdf、text/pdf 两项）`);
        }
      }
      if (window.MimeTypeArray && mt && Object.getPrototypeOf(mt) !== MimeTypeArray.prototype) hits.push("navigator.mimeTypes 原型不是 MimeTypeArray");
    } catch (e) { hits.push("plugins 结构访问抛错"); }
    R.stealthHits = hits;
    setProbe("stealth", hits.length ? `抓获 ${hits.length} 处隐身补丁残留：${hits.slice(0, 3).join(" · ")}${hits.length > 3 ? "…" : ""}` : "webdriver、window.chrome、srcdoc iframe、原生 getter 错误栈与插件结构均为原生形态", {
      tone: hits.length ? "bad" : "ok", why: hits.join("\n")
    });
  }

  // (5) Page focus / visibility / sticky user activation
  function probeFocus() {
    const hf = typeof document.hasFocus === "function" ? document.hasFocus() : null;
    const vis = document.visibilityState || "";
    const act = navigator.userActivation;
    R.pageFocus = { hf, vis, everActive: act ? act.hasBeenActive : null };
    const parts = [vis === "visible" ? "页面可见" : vis === "hidden" ? "后台 / 隐藏标签页" : vis || "未知可见性", hf === true ? "窗口已聚焦" : hf === false ? "窗口未聚焦" : "", act ? (act.hasBeenActive ? "已有用户激活手势" : "尚无用户激活手势") : ""].filter(Boolean);
    const odd = vis === "visible" && hf === false && act && !act.hasBeenActive && (R.winHeadless || (R.headlessHits || []).length);
    setProbe("focus", parts.join(" · "), { tone: odd ? "warn" : "neutral" });
  }

  // (6) CPU architecture via Float32 NaN bit pattern (FingerprintJS architecture source)
  function probeCpuArch() {
    let byte = null;
    try {
      const f = new Float32Array(1), u = new Uint8Array(f.buffer);
      f[0] = Infinity;
      f[0] = f[0] - f[0];
      byte = u[3];
    } catch (e) {}
    const arch = byte === 255 ? "x86" : byte === 127 ? "arm" : "";
    R.cpuArch = arch;
    const ua = navigator.userAgent || "";
    const claims = [];
    if (R.hi?.architecture) claims.push(["高熵 Client Hints", /arm/i.test(R.hi.architecture) ? "arm" : /x86/i.test(R.hi.architecture) ? "x86" : ""]);
    if (/Android|iPhone|iPad|iPod/.test(ua)) claims.push(["移动端 UA", "arm"]);
    if (/aarch64|armv\d/i.test(ua)) claims.push(["UA", "arm"]);
    if (/x86_64|Win64; x64|WOW64|i686/i.test(ua) && !/Android/.test(ua)) claims.push(["UA", "x86"]);
    const conflict = arch ? claims.filter(([, c]) => c && c !== arch && !(c === "x86" && /Windows/.test(ua))) : [];
    R.cpuArchConflict = conflict.length ? `${conflict[0][0]} 自报 ${conflict[0][1]}，浮点 NaN 位模式实测 ${arch}` : "";
    const emu = arch === "x86" && /Android|iPhone|iPad/.test(ua);
    setProbe("cpuarch", arch
      ? `${arch === "x86" ? "x86 / x86-64" : "ARM / AArch64"} (NaN 高字节 0x${byte.toString(16)})${conflict.length ? ` · 与${conflict[0][0]}矛盾` : ""}${emu ? " · 手机 UA 跑在 x86 上：模拟器 / 云手机特征" : ""}`
      : "无法判定（非标准浮点实现）",
    { tone: conflict.length || emu ? "bad" : "neutral" });
  }

  // (7) CSS system font keywords & system colors → host OS (CreepJS style)
  function probeSysFont() {
    try {
      const el = document.createElement("div");
      el.style.cssText = "position:absolute;left:-9999px;top:0";
      document.body.appendChild(el);
      const fams = {};
      for (const k of ["caption", "icon", "menu", "message-box", "small-caption", "status-bar"]) {
        el.style.font = k;
        const cs = getComputedStyle(el);
        fams[k] = `${cs.fontFamily} ${cs.fontSize}`;
      }
      const cols = [];
      for (const c of ["Canvas", "CanvasText", "ButtonFace", "ButtonText", "Field", "Highlight", "HighlightText", "LinkText", "GrayText", "AccentColor"]) {
        el.style.color = c;
        cols.push(getComputedStyle(el).color);
      }
      el.remove();
      const all = Object.values(fams).join(" | ");
      const winFam = /Segoe UI|Microsoft YaHei|Tahoma|MS Shell Dlg|Yu Gothic UI|Malgun Gothic|Microsoft JhengHei/i.test(all);
      const appleFam = /-apple-system|BlinkMacSystemFont|\.AppleSystemUIFont|\.SF NS|SF Pro|San Francisco|Lucida Grande/i.test(all);
      const linuxFam = /Cantarell|Ubuntu|DejaVu|Liberation|Noto Sans(?! CJK SC)|Droid Sans/i.test(all);
      const hint = winFam ? "Windows" : appleFam ? "Apple" : linuxFam ? "Linux" : "";
      const os = R.dev?.os || "";
      let conflict = "";
      if (hint === "Windows" && /^(macOS|iOS|iPadOS|Linux|Android)$/.test(os)) conflict = `系统字体关键字解析为 Windows 字体，却自报 ${os}`;
      else if (hint === "Apple" && /^(Windows|Linux|Android)$/.test(os)) conflict = `系统字体关键字解析为 Apple 字体，却自报 ${os}`;
      else if (hint === "Linux" && /^(Windows|macOS|iOS|iPadOS)$/.test(os)) conflict = `系统字体关键字解析为 Linux 桌面字体，却自报 ${os}`;
      R.sysFontConflict = conflict;
      const caption = (fams.caption || "").split(" ")[0].replace(/"/g, "");
      shortHashAsync(cols.join("|")).then(h => { R.sysColorHash = h; });
      setProbe("sysfont", conflict ? conflict : `caption=${caption || "-"} · 推断宿主 ${hint || "未定"} · 系统色 ${cols.length} 项`, {
        tone: conflict ? "bad" : "neutral",
        why: `${Object.entries(fams).map(([k, v]) => `${k}: ${v}`).join("\n")}\n系统色: ${cols.join(", ")}`
      });
    } catch (e) { setNA("sysfont"); }
  }
  async function shortHashAsync(s) { return shortHash(await sha256(s)); }

  // (8) navigator vendor-level property consistency (Akamai / BotD / FingerprintJS vendorFlavors)
  const VENDOR_FLAVORS = ["chrome", "safari", "__crWeb", "__gCrWeb", "yandex", "__yb", "__ybro", "__firefox__", "__edgeTrackingPreventionStatistics", "webkit", "oprt", "samsungAr", "ucweb", "UCShellJava", "puffinDevice"];
  function probeNavProps() {
    const ua = navigator.userAgent || "";
    const cb = claimedBrowser();
    const issues = [];
    const vendor = navigator.vendor;
    if ((cb === "Chrome" || cb === "Edge" || cb === "Opera") && vendor !== "Google Inc.") issues.push(`vendor="${vendor}" 与 Chromium 系不符`);
    if ((cb === "Safari" || cb === "iOSWebKit") && vendor !== "Apple Computer, Inc.") issues.push(`vendor="${vendor}" 与 Safari/WebKit 不符`);
    if (cb === "Firefox" && vendor !== "") issues.push(`Firefox 的 vendor 应为空，实为 "${vendor}"`);
    const ps = navigator.productSub;
    if (cb === "Firefox" && ps !== "20100101") issues.push(`productSub=${ps}（Firefox 应为 20100101）`);
    if (cb && cb !== "Firefox" && ps && ps !== "20030107") issues.push(`productSub=${ps}（Chromium/WebKit 应为 20030107）`);
    let evalLen = null;
    try { evalLen = Function.prototype.toString.call(eval).length; } catch (e) {}
    if (evalLen != null) {
      if ((cb === "Chrome" || cb === "Edge" || cb === "Opera") && evalLen !== 33) issues.push(`eval.toString 长度 ${evalLen}（V8 为 33）`);
      if ((cb === "Firefox" || cb === "Safari") && evalLen !== 37) issues.push(`eval.toString 长度 ${evalLen}（SpiderMonkey/JSC 为 37）`);
    }
    const av = navigator.appVersion || "";
    if ((cb === "Chrome" || cb === "Edge" || cb === "Opera" || cb === "Safari") && av && ua.startsWith("Mozilla/") && av !== ua.slice(8)) issues.push("appVersion 与 User-Agent 不同步");
    if (/Headless/i.test(av)) issues.push("appVersion 含 Headless");
    if (cb !== "Firefox" && navigator.oscpu !== undefined) issues.push("非 Firefox 却暴露 navigator.oscpu");
    if (cb !== "Firefox" && navigator.buildID !== undefined) issues.push("非 Firefox 却暴露 navigator.buildID");
    if (cb === "Firefox" && navigator.oscpu) {
      const o = navigator.oscpu;
      const osO = /Windows/.test(o) ? "Windows" : /Mac/.test(o) ? "macOS" : /Linux/.test(o) ? "Linux" : "";
      const osU = /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Linux|Android/.test(ua) ? "Linux" : "";
      if (osO && osU && osO !== osU) issues.push(`oscpu (${o}) 与 UA 系统 (${osU}) 矛盾`);
    }
    if ((cb === "Firefox" || cb === "Safari") && navigator.userAgentData) issues.push(`自称 ${cb} 却暴露 Chromium 专有 userAgentData`);
    try {
      const brands = (navigator.userAgentData?.brands || []).map(b => b.brand);
      if (brands.includes("Microsoft Edge") && !/Edg\//.test(ua)) issues.push("userAgentData 为 Edge，UA 却不是 Edge");
      if (brands.includes("Google Chrome") && /Edg\/|OPR\//.test(ua)) issues.push("userAgentData 为 Google Chrome，UA 却是 Edge/Opera");
      if (brands.includes("Google Chrome")) {
        const v = document.createElement("video");
        if (v.canPlayType && v.canPlayType('video/mp4; codecs="avc1.42E01E"') === "") issues.push("自称 Google Chrome 却不支持 H.264（开源 Chromium / 自动化内置浏览器）");
      }
    } catch (e) {}
    if (cb === "Safari" && /Macintosh|iPhone|iPad/.test(ua) && window.isSecureContext && typeof window.ApplePaySession === "undefined") issues.push("自称 Safari 却缺少 ApplePaySession");
    const flavors = VENDOR_FLAVORS.filter(k => { try { return k in window; } catch (e) { return false; } });
    if ((cb === "Chrome" || cb === "Edge") && flavors.includes("safari") && !flavors.includes("chrome")) issues.push("Chromium UA 却只有 Safari 厂商对象");
    R.navPropIssues = issues;
    setProbe("navprops", issues.length
      ? `${issues.length} 处厂商属性矛盾：${issues.slice(0, 3).join(" · ")}${issues.length > 3 ? "…" : ""}`
      : `vendor="${vendor}" · productSub ${ps || "-"} · eval ${evalLen ?? "-"} · 厂商对象 ${flavors.join("/") || "无"}，与 ${cb || "当前浏览器"} 一致`,
    { tone: issues.length ? "bad" : "ok", why: issues.join("\n") });
  }

  // (9) Date().toString() time-zone name language (leaks browser UI / ICU locale independent of navigator.languages)
  function probeTzName() {
    let name = "", longName = "";
    try { name = (/\(([^)]+)\)\s*$/.exec(new Date().toString()) || [])[1] || ""; } catch (e) {}
    try { longName = new Intl.DateTimeFormat(undefined, { timeZoneName: "long" }).formatToParts(new Date()).find(p => p.type === "timeZoneName")?.value || ""; } catch (e) {}
    const scriptOf = t => /[\u3040-\u30ff]/.test(t) ? "ja" : /[\uac00-\ud7af]/.test(t) ? "ko" : /[\u4e00-\u9fff]/.test(t) ? "zh" : /[\u0400-\u04ff]/.test(t) ? "ru" : /[\u0600-\u06ff]/.test(t) ? "ar" : /[\u0e00-\u0e7f]/.test(t) ? "th" : "";
    const sc = scriptOf(name);
    const prim = (R.langs || navigator.languages || []).map(l => String(l).toLowerCase().split("-")[0]);
    const leak = sc && !prim.includes(sc) && !(sc === "zh" && prim.includes("ja"));
    R.tzNameLeak = leak ? `Date 时区名「${name}」暴露 ${({ zh: "中文", ja: "日文", ko: "韩文", ru: "俄文", ar: "阿拉伯文", th: "泰文" })[sc]} 界面，而 navigator.languages 为 ${prim.slice(0, 2).join(",") || "空"}` : "";
    setProbe("tzname", name ? `${name}${longName && longName !== name ? ` · Intl: ${longName}` : ""}${leak ? " · 界面语言泄露" : ""}` : "未暴露时区名称", { tone: leak ? "warn" : "neutral" });
  }

  // (10) Sec-CH-UA GREASE brand algorithm (Chromium: seed = major version)
  function expectedGreaseBrand(major) {
    const ch = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    return { brand: `Not${ch[major % 11]}A${ch[(major + 1) % 11]}Brand`, version: ["8", "99", "24"][major % 3] };
  }
  function parseChUa(h) {
    return [...String(h || "").matchAll(/"([^"]+)"\s*;\s*v="([^"]+)"/g)].map(m => ({ brand: m[1], version: m[2] }));
  }
  function checkGrease(list, src) {
    if (!list.length) return null;
    const chromium = list.find(b => b.brand === "Chromium") || list.find(b => /Google Chrome|Microsoft Edge|Opera|Brave/.test(b.brand));
    const major = chromium ? parseInt(chromium.version, 10) : 0;
    const grease = list.find(b => /Not[^A-Za-z0-9]*A[^A-Za-z0-9]*Brand/i.test(b.brand));
    if (!major || major < 110) return { src, major, skip: true };
    const exp = expectedGreaseBrand(major);
    if (!grease) return { src, major, ok: false, why: `${src} 缺少 GREASE 品牌（应为 "${exp.brand}";v="${exp.version}"）` };
    const verMaj = String(grease.version).split(".")[0];
    if (grease.brand !== exp.brand || verMaj !== exp.version) {
      return { src, major, ok: false, why: `${src} GREASE 为 "${grease.brand}";v="${grease.version}"，Chromium ${major} 应为 "${exp.brand}";v="${exp.version}"` };
    }
    // 3 品牌时的固定排列：list=[GREASE, Chromium, 品牌]，shuffled[order[i]] = list[i]，order = ORDERS[major % 6]
    if (list.length === 3 && chromium.brand === "Chromium") {
      const third = list.find(b => b !== grease && b.brand !== "Chromium");
      const ORDERS = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
      const order = ORDERS[major % 6];
      const expOrder = [];
      [grease.brand, "Chromium", third?.brand].forEach((b, i) => { expOrder[order[i]] = b; });
      const got = list.map(b => b.brand);
      if (third && got.join("|") !== expOrder.join("|")) {
        return { src, major, ok: false, why: `${src} 品牌顺序 [${got.join(", ")}] 不符合 Chromium ${major} 的固定排列 [${expOrder.join(", ")}]` };
      }
    }
    return { src, major, ok: true, got: `"${grease.brand}";v="${grease.version}"` };
  }
  function probeChGrease() {
    const hdr = R.srv?.headers?.["sec-ch-ua"] || "";
    const js = (navigator.userAgentData?.brands || []).map(b => ({ brand: b.brand, version: b.version }));
    if (!hdr && !js.length) { R.greaseIssues = []; return setNA("chgrease", "非 Chromium 浏览器（不发送 Sec-CH-UA）"); }
    const res = [checkGrease(parseChUa(hdr), "HTTP 头"), checkGrease(js, "JS userAgentData")].filter(Boolean);
    const bad = res.filter(r => r.ok === false);
    R.greaseIssues = bad.map(r => r.why);
    const any = res.find(r => !r.skip);
    if (!any) return setProbe("chgrease", `Chromium ${res[0]?.major || "?"} 早于 110，跳过 GREASE 算法校验`, { na: true });
    setProbe("chgrease", bad.length ? `品牌伪造：${bad[0].why}` : `GREASE ${any.got} 与品牌顺序均符合 Chromium ${any.major} 生成算法`, { tone: bad.length ? "bad" : "ok" });
  }

  // (11) AI / social platform regional availability for the actual per-platform egress
  const PLATFORM_BLOCKED = {
    // 官方页面核对于 2026-11-24：help.openai.com supported-countries / anthropic.com/supported-countries / ai.google.dev available-regions
    OpenAI: ["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY", "VE"],
    Claude: ["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY", "VE", "YE", "AF", "MM", "XK", "EH"],
    Gemini: ["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "AF", "MM"],
    TikTok: ["CN", "HK", "IN", "IR", "KP", "AF"]
  };
  function probeAiGeo() {
    const ex = R.exits || {};
    const ccOf = { OpenAI: ex.ex_gpt?.cc || R.ipCC, Claude: ex.ex_claude?.cc || R.ipCC, Gemini: ex.ex_intl?.cc || R.ipCC, TikTok: R.ipCC };
    const rows = Object.entries(PLATFORM_BLOCKED).map(([p, list]) => {
      const cc = (ccOf[p] || "").toUpperCase();
      return { p, cc, blocked: !!cc && list.includes(cc) };
    });
    if (!rows.some(r => r.cc)) return setNA("aigeo", "等待出口国家识别");
    const blocked = rows.filter(r => r.blocked);
    R.aiGeoBlocked = blocked.map(r => `${r.p}(${r.cc})`);
    setProbe("aigeo", rows.map(r => `${r.p} ${r.cc ? flagEmoji(r.cc) + r.cc : "?"} ${r.blocked ? "✕" : "✓"}`).join(" · "), {
      tone: blocked.length ? "bad" : "ok",
      why: "按各平台实际分流出口国家比对官方不提供服务的地区（参考名单，以官方最新公告为准）。"
    });
  }

  // (12) AudioContext base/output latency (FingerprintJS audioBaseLatency)
  function probeAudioLatency() {
    try {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return setNA("audiolat");
      const ac = new AC();
      const bl = ac.baseLatency, ol = ac.outputLatency, sr = ac.sampleRate;
      try { ac.close(); } catch (e) {}
      if (bl == null) return setNA("audiolat", "未暴露 baseLatency");
      const frames = Math.round(bl * sr);
      R.audioLatency = { bl, ol, sr, frames };
      setProbe("audiolat", `baseLatency ${(bl * 1000).toFixed(2)} ms (${frames} 帧 @ ${sr} Hz)${ol ? ` · outputLatency ${(ol * 1000).toFixed(1)} ms` : ""}`);
    } catch (e) { setNA("audiolat"); }
  }

  /* ---------- v7.6 Deep Protocol, Launch-Flag & Cross-Realm Probes (7 client items + h2akamai server item) ---------- */
  let bootPopupChecked = false;
  let bootPopupOpened = null;

  // (13) Popup blocker flag (--disable-popup-blocking): only auto-invoked when transient userActivation is inactive
  function probePopupBlocker() {
    if (!bootPopupChecked && !(navigator.userActivation && navigator.userActivation.isActive)) {
      bootPopupChecked = true;
      try {
        const w = window.open("about:blank", "_blank", "width=80,height=80,left=9999,top=9999");
        if (w) {
          bootPopupOpened = true;
          try { w.close(); } catch (e) {}
        } else {
          bootPopupOpened = false;
        }
      } catch (e) {
        bootPopupOpened = false;
      }
    }
    R.popupDisabled = bootPopupOpened === true;
    if (bootPopupOpened == null) {
      return setNA("popupblk", "当前处于用户手势激活窗口期，跳过自动弹窗测试以免打扰");
    }
    setProbe("popupblk", bootPopupOpened
      ? "无用户手势下 window.open 未被拦截（已毫秒级关闭）：检出 --disable-popup-blocking 或全局放行弹窗"
      : "无手势弹窗已被浏览器默认拦截（正常真人策略）",
    { tone: bootPopupOpened ? "warn" : "ok" });
  }

  // (14) IPC flooding protection flag (--disable-ipc-flooding-protection) via hidden same-origin blank iframe
  async function probeIpcFlood() {
    const fr = document.createElement("iframe");
    fr.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden;pointer-events:none";
    fr.setAttribute("aria-hidden", "true");
    const loaded = new Promise(r => { fr.onload = () => r(true); fr.onerror = () => r(false); setTimeout(() => r(false), 1800); });
    fr.src = "./api/who/blank";
    document.body.appendChild(fr);
    const ok = await loaded;
    let applied = 0, errName = "";
    if (ok && fr.contentWindow?.history) {
      try {
        const h = fr.contentWindow.history;
        for (let i = 1; i <= 260; i++) {
          h.replaceState(i, "");
          if (h.state === i) applied++;
        }
      } catch (e) { errName = e?.name || "Error"; }
    }
    fr.remove();
    if (!ok || !applied) {
      R.ipcFloodDisabled = false;
      return setNA("ipcflood", errName ? `受安全策略限制 (${errName})` : "空白探针页未就绪");
    }
    const isChromium = R.engine === "V8";
    const disabled = isChromium && applied >= 240;
    R.ipcFloodDisabled = disabled;
    if (disabled) R.botHits = Array.from(new Set([...(R.botHits || []), "启动参数 --disable-ipc-flooding-protection (replaceState 未限流)"]));
    setProbe("ipcflood", disabled
      ? `260/260 次 replaceState 全部放行：检出自动化启动参数 --disable-ipc-flooding-protection`
      : isChromium
      ? `在第 ${applied}/260 次触发 Blink IPC 洪泛限流保护（正常浏览器上限≈200）`
      : `执行 ${applied}/260 次（非 Chromium 内核限流阈值不同）`,
    { tone: disabled ? "bad" : "ok" });
  }

  // (15) CSP bypass detection (Playwright bypassCSP: true / CDP Page.setBypassCSP)
  async function probeCspBypass() {
    const token = `__wp_csp_${Math.random().toString(36).slice(2, 9)}`;
    window[token] = false;
    const cf = document.createElement("iframe");
    cf.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden;pointer-events:none";
    cf.setAttribute("aria-hidden", "true");
    const done = new Promise(r => { cf.onload = () => setTimeout(r, 25); setTimeout(r, 450); });
    cf.srcdoc = `<!doctype html><head><meta http-equiv="Content-Security-Policy" content="script-src 'none'"></head><body><script>try{parent["${token}"]=true;}catch(e){}<\/script></body>`;
    document.body.appendChild(cf);
    await done;
    cf.remove();
    const bypassed = window[token] === true;
    try { delete window[token]; } catch (e) {}
    R.cspBypassed = bypassed;
    if (bypassed) R.botHits = Array.from(new Set([...(R.botHits || []), "CSP 策略被强制绕过 (Page.setBypassCSP / bypassCSP)"]));
    setProbe("cspbypass", bypassed
      ? "高危：script-src 'none' 下内联脚本仍被执行，实锤开启了 CDP setBypassCSP / Playwright bypassCSP！"
      : "隔离沙箱 script-src 'none' 正常生效，未见 CSP 绕过",
    { tone: bypassed ? "bad" : "ok" });
  }

  // (16) Worker OffscreenCanvas WebGL renderer cross-check (CreepJS hasBadWebGL)
  async function probeGlWorker() {
    if (typeof Worker !== "function" || typeof OffscreenCanvas !== "function") {
      R.glWorkerMismatch = "";
      return setNA("glworker", "当前内核不支持 Worker OffscreenCanvas");
    }
    const code = `try {
      const c = new OffscreenCanvas(16, 16);
      const gl = c.getContext("webgl2") || c.getContext("webgl");
      if (!gl) { postMessage({ ok: false }); } else {
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        postMessage({
          ok: true,
          vendor: dbg ? String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || "") : String(gl.getParameter(gl.VENDOR) || ""),
          renderer: dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "") : String(gl.getParameter(gl.RENDERER) || "")
        });
      }
    } catch (e) { postMessage({ ok: false, err: String(e) }); }`;
    let res = null;
    try {
      const u = URL.createObjectURL(new Blob([code], { type: "application/javascript" }));
      const wk = new Worker(u);
      res = await within(new Promise(r => { wk.onmessage = e => r(e.data); wk.onerror = () => r(null); }), 1800, null);
      wk.terminate();
      URL.revokeObjectURL(u);
    } catch (e) {}
    if (!res || !res.ok || !res.renderer) {
      R.glWorkerMismatch = "";
      return setNA("glworker", "Worker 未暴露显卡渲染器");
    }
    const norm = s => String(s || "").replace(/\s+/g, " ").trim();
    const mainR = norm(R.gpuRaw || "");
    const wkR = norm(res.renderer);
    const wkSoft = /SwiftShader|llvmpipe|Basic Render Driver|Software Rasterizer/i.test(wkR);
    let mismatch = "";
    if (mainR && wkR && mainR !== wkR) {
      mismatch = `主线程自报「${cleanGpuName(mainR)}」，但 Worker 线程实测为「${cleanGpuName(wkR)}」`;
    } else if (wkSoft && !R.gpuSoft) {
      mismatch = `Worker 线程暴露软件虚拟显卡 (${cleanGpuName(wkR)})`;
    }
    R.glWorkerMismatch = mismatch;
    setProbe("glworker", mismatch ? `跨线程穿帮：${mismatch}` : `主线程与 Worker 显卡一致 (${cleanGpuName(wkR)})`, {
      tone: mismatch ? "bad" : "ok",
      why: `Main: ${mainR || "-"}\nWorker: ${wkR} (${res.vendor || "-"})`
    });
  }

  // (17) Local-only WebRTC SDP Offer stack, DTLS/SCTP template & ice-ufrag / Origin engine cross-check
  async function probeRtcSdp() {
    const PC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    R.ufragConflict = "";
    if (typeof PC !== "function") {
      setNA("ufrag", "WebRTC 已禁用或不可用");
      return setNA("rtcsdp", "WebRTC 已禁用或不可用");
    }
    let pc = null;
    try {
      pc = new PC({ iceServers: [] });
      pc.createDataChannel("wp");
      if (typeof pc.addTransceiver === "function") pc.addTransceiver("audio", { direction: "recvonly" });
      const offer = await within(pc.createOffer(), 1800, null);
      const sdp = String(offer?.sdp || "");
      if (!sdp) {
        setNA("ufrag", "SDP Offer 为空");
        return setNA("rtcsdp", "SDP Offer 为空");
      }
      const iceOpt = ((/^a=ice-options:(.+)$/m.exec(sdp) || [])[1] || "").trim();
      const dtlsHash = ((/^a=fingerprint:(\S+)/m.exec(sdp) || [])[1] || "").trim();
      const maxMsg = ((/^a=max-message-size:(\d+)/m.exec(sdp) || [])[1] || "").trim();
      const extUris = [...sdp.matchAll(/^a=extmap:\d+(?:\/\S+)?\s+(\S+)/gm)].map(m => m[1]);
      const codecs = [...sdp.matchAll(/^a=rtpmap:\d+\s+([^/\r\n]+)/gm)].map(m => m[1]);
      const sig = shortHash(await sha256([iceOpt, dtlsHash, maxMsg, ...extUris, ...codecs].join("|")));
      R.rtcSdpSig = sig;
      setProbe("rtcsdp", `${sig} · DTLS ${dtlsHash || "-"} · SCTP ${maxMsg ? Math.round(+maxMsg / 1024) + "KB" : "-"} · ${codecs.slice(0, 3).join("/")} (${extUris.length} 扩展)`, {
        why: `ice-options: ${iceOpt || "无"}\ncodecs: ${codecs.join(", ")}\nextmap: ${extUris.length} 项`
      });

      const oLine = ((/^o=(.+)$/m.exec(sdp) || [])[1] || "").trim();
      const ufragVal = ((/^a=ice-ufrag:([^\r\n]+)/m.exec(sdp) || [])[1] || "").trim();
      const sdpMoz = /THIS_IS_SDPARTA/i.test(oLine);
      const ulen = ufragVal.length;
      const cb = claimedBrowser();
      let uConflict = "";
      if (cb === "Firefox" && (!sdpMoz || ulen === 4)) {
        uConflict = `自称 Firefox，但 SDP 呈现 libwebrtc 特征 (Origin=${sdpMoz ? "SDPARTA" : "o=-"}, ufrag=${ulen}字符)`;
      } else if ((cb === "Chrome" || cb === "Edge" || cb === "Opera") && (sdpMoz || ulen === 8)) {
        uConflict = `自称 ${cb}，但 SDP 暴露 Firefox nICEr 媒体栈特征 (${sdpMoz ? "THIS_IS_SDPARTA" : `ufrag=${ulen}字符`})`;
      } else if ((cb === "Safari" || cb === "iOSWebKit") && sdpMoz) {
        uConflict = `自称 ${cb}，但 SDP 暴露 Firefox 专属 THIS_IS_SDPARTA 签名`;
      }
      R.ufragConflict = uConflict;
      const engGuess = sdpMoz || ulen === 8 ? "Firefox nICEr (8字符)" : ulen === 4 ? "libwebrtc (4字符)" : `ufrag=${ulen}字符`;
      setProbe("ufrag", uConflict ? `引擎穿帮：${uConflict}` : `${engGuess} · Origin=${sdpMoz ? "THIS_IS_SDPARTA" : "o=-"} · 与 ${cb || "当前内核"} 吻合`, {
        tone: uConflict ? "bad" : "ok",
        why: `o=${oLine.slice(0, 72)}\na=ice-ufrag:${ufragVal} (长度 ${ulen})`
      });
    } catch (e) {
      setNA("rtcsdp", "SDP 协商受限");
      setNA("ufrag", "SDP 协商受限");
    } finally {
      try { pc && pc.close(); } catch (e) {}
    }
  }

  // (18) Deep Intl constructors default-locale consistency (6 constructors + Number.toLocaleString)
  function probeIntlDeep() {
    const locs = [];
    const collect = (name, fn) => {
      try {
        const v = fn()?.resolvedOptions?.()?.locale;
        if (v) locs.push([name, String(v)]);
      } catch (e) {}
    };
    collect("DateTime", () => new Intl.DateTimeFormat());
    collect("Number", () => new Intl.NumberFormat());
    if (Intl.RelativeTimeFormat) collect("RelativeTime", () => new Intl.RelativeTimeFormat());
    if (Intl.PluralRules) collect("PluralRules", () => new Intl.PluralRules());
    if (Intl.DisplayNames) collect("DisplayNames", () => new Intl.DisplayNames(undefined, { type: "region" }));
    if (Intl.ListFormat) collect("ListFormat", () => new Intl.ListFormat());
    if (!locs.length) return setNA("intldeep");
    const prims = new Set(locs.map(([, l]) => l.toLowerCase().split("-")[0]));
    const mismatch = prims.size > 1;
    R.intlDeepMismatch = mismatch ? locs.map(([k, v]) => `${k}=${v}`).join(", ") : "";
    setProbe("intldeep", mismatch
      ? `构造器默认语种分裂：${R.intlDeepMismatch}`
      : `6 大构造器统一为 ${locs[0][1]}（主语种一致）`,
    { tone: mismatch ? "bad" : "ok", why: locs.map(([k, v]) => `${k}: ${v}`).join("\n") });
  }

  // (19) Error.prototype.stack syntax & captureStackTrace vs claimed engine
  function probeStackFmt() {
    let st = "";
    try { throw new Error("wp"); } catch (e) { st = String(e.stack || ""); }
    const v8Style = /\n\s+at\s+/.test(st);
    const atSignStyle = !v8Style && /@\S+:\d+/.test(st);
    const hasCapture = typeof Error.captureStackTrace === "function";
    const stackEng = v8Style ? "V8" : atSignStyle ? "SpiderMonkey / JSC" : "Unknown";
    const cb = claimedBrowser();
    let conflict = "";
    if ((cb === "Chrome" || cb === "Edge" || cb === "Opera") && atSignStyle) {
      conflict = `自称 ${cb}，但 Error.stack 呈现 Firefox/Safari 的 '@' 格式`;
    } else if ((cb === "Firefox" || cb === "Safari") && v8Style) {
      conflict = `自称 ${cb}，但 Error.stack 呈现 V8 独有的 '    at ' 缩进格式`;
    }
    R.stackFmtConflict = conflict;
    setProbe("stackfmt", conflict || `堆栈语法为 ${stackEng} 格式 · captureStackTrace=${hasCapture ? "支持" : "无"}`, {
      tone: conflict ? "bad" : "ok"
    });
  }

  /* ---------- v7.7 Deep Protocol, QUIC Initial JA4Q, GPU ALU & Multi-Worker Probes ---------- */

  // (20) Server-initiated RFC 6455 WebSocket 0x89 Ping -> 0x8A Pong control-frame RTT
  async function probeWsPing() {
    if (typeof WebSocket !== "function") {
      R.wsPingRtt = null;
      return setNA("wsping", "WebSocket 不可用");
    }
    const wsUrl = new URL("./api/who/ws-ping", location.href);
    wsUrl.protocol = wsUrl.protocol === "https:" ? "wss:" : "ws:";
    wsUrl.searchParams.set("t", String(Date.now()));
    let data = null;
    try {
      data = await new Promise(resolve => {
        let settled = false;
        const done = v => { if (!settled) { settled = true; clearTimeout(tm); resolve(v); } };
        const ws = new WebSocket(wsUrl.href);
        const tm = setTimeout(() => { try { ws.close(); } catch (e) {} done(null); }, 4200);
        ws.onmessage = ev => {
          try { done(JSON.parse(ev.data)); } catch (e) { done(null); }
          try { ws.close(); } catch (e) {}
        };
        ws.onerror = () => done(null);
        ws.onclose = () => done(null);
      });
    } catch (e) {}
    const rtt = data?.wsPingRttMs;
    if (rtt == null) {
      R.wsPingRtt = null;
      return setNA("wsping", "网关未透传 WebSocket Upgrade 或连接受限");
    }
    const wsMs = Math.max(1, Math.round(rtt));
    R.wsPingRtt = wsMs;
    const cmpParts = [`控制帧 Pong ${wsMs} ms`];
    let tone = "ok";
    if (R.httpRtt != null) {
      const gap = Math.round(R.httpRtt - wsMs);
      cmpParts.push(`HTTP ${R.httpRtt} ms`);
      if (gap >= 85) {
        cmpParts.push(`JS 主线程延迟 +${gap} ms`);
        tone = "warn";
      }
    }
    if (R.srvTcpRtt != null) {
      const relay = wsMs - R.srvTcpRtt;
      cmpParts.push(`TCP 握手 ${R.srvTcpRtt} ms`);
      if (relay >= 95) {
        cmpParts.push(`代理多绕 +${relay} ms`);
        tone = "bad";
      } else if (relay >= 45 && tone === "ok") {
        tone = "warn";
      }
    }
    setProbe("wsping", cmpParts.join(" · "), {
      tone,
      why: `服务端 RFC 6455 0x89 Ping → 0x8A Pong 两轮实测: ${(data.samples || []).map(x => x + "ms").join(", ")}`
    });
  }

  // (21) Cross-connection TLS ClientHello extension permutation & PSK resumption check
  async function probeTlsPerm() {
    R.tlsStaticPerm = false;
    let perm = R.srv?.packet?.tlsPermutation || null;
    if (!perm || (perm.samples || 0) < 2) {
      const r2 = await getJSON(`./api/who/tls2?t=${Date.now()}`, 3500, "include").catch(() => null);
      if (r2?.tlsPermutation) perm = r2.tlsPermutation;
    }
    const cnt = perm?.samples || 0;
    if (!perm || cnt === 0) {
      return setNA("tlsperm", location.protocol === "https:" ? "连接复用未捕获新 ClientHello" : "明文 HTTP 未经 TLS 握手（线上 HTTPS 自动核验）");
    }
    if (cnt < 2 || perm.permuted == null) {
      return setProbe("tlsperm", `已捕获 1 次握手${perm.pskSeen ? " (含 PSK 会话票据)" : ""} · 点击「重新检测」比对二次扩展洗牌`, { tone: "neutral" });
    }
    const claimedChrome = +((/Chrome\/(\d+)/.exec(navigator.userAgent) || [])[1] || 0);
    const shouldPermute = R.engine === "V8" && claimedChrome >= 112;
    const staticAnomaly = shouldPermute && perm.permuted === false;
    R.tlsStaticPerm = staticAnomaly;
    const pskTxt = perm.pskSeen ? "PSK 会话恢复正常" : "无 PSK 票据";
    if (staticAnomaly) {
      setProbe("tlsperm", `静态模板异常：连续 ${cnt} 次独立握手扩展排列 100% 雷同（Chrome 110+ 必随机洗牌）`, {
        tone: "bad",
        why: `独立握手数: ${cnt} · 不同 JA3 哈希数: ${perm.distinctJa3 || 1} · ${pskTxt}`
      });
    } else if (perm.permuted) {
      setProbe("tlsperm", `扩展随机洗牌已验证（${cnt} 次握手产生 ${perm.distinctJa3 || 2} 种 JA3 · ${pskTxt}）`, { tone: "ok" });
    } else {
      setProbe("tlsperm", `${cnt} 次握手扩展顺序固定（符合 ${claimedBrowser() || "非 Chromium"} 栈特征 · ${pskTxt}）`, { tone: "ok" });
    }
  }

  // (22) QUIC v1/v2 Initial decryption, JA4Q & 0x0039 transport parameters stack attribution
  async function probeQuicParams() {
    R.quicStackMismatch = "";
    R.quicFp = null;
    if (location.protocol !== "https:") {
      return setNA("quicpar", "仅 HTTPS 环境可触发 UDP 443 QUIC Initial 采集");
    }
    if (typeof WebTransport === "function") {
      try {
        const wt = new WebTransport(`https://${location.host}/api/who/quic-wt?t=${Date.now()}`);
        wt.ready.catch(() => {});
        wt.closed.catch(() => {});
        await new Promise(r => setTimeout(r, 320));
        try { wt.close(); } catch (e) {}
      } catch (e) {}
    }
    const qRes = await getJSON(`./api/who/quic?t=${Date.now()}`, 3000, "omit").catch(() => null);
    const q = qRes?.quic || R.srv?.packet?.quic || null;
    if (!q) {
      if (typeof WebTransport !== "function") {
        return setNA("quicpar", "当前内核不支持 WebTransport 主动触发（未捕获 UDP 443 首包）");
      }
      if (qRes && qRes.collectorActive === false) {
        return setNA("quicpar", "服务端未启用 UDP 443 QUIC 嗅探器");
      }
      return setProbe("quicpar", "UDP 443 QUIC 首包未达服务端（代理仅转发 TCP 或防火墙拦截 UDP）", { tone: "neutral" });
    }
    R.quicFp = q;
    const cb = claimedBrowser();
    const fam = q.stackFamily || "";
    let mismatch = "";
    if (fam === "quic-go") {
      mismatch = `QUIC 传输参数暴露代理库 ${q.stackGuess}（代理客户端代发了 UDP QUIC）`;
    } else if ((cb === "Chrome" || cb === "Edge" || cb === "Opera") && (fam === "neqo" || fam === "nw_quic")) {
      mismatch = `UA 自称 ${cb}，但 QUIC Initial 却是 ${q.stackGuess}`;
    } else if (cb === "Firefox" && (fam === "quiche" || fam === "nw_quic")) {
      mismatch = `UA 自称 Firefox，但 QUIC Initial 却是 ${q.stackGuess}`;
    } else if ((cb === "Safari" || cb === "iOSWebKit") && (fam === "quiche" || fam === "neqo")) {
      mismatch = `UA 自称 Safari/WebKit，但 QUIC Initial 却是 ${q.stackGuess}`;
    }
    R.quicStackMismatch = mismatch;
    const tp = q.transportParams || {};
    const winKb = tp.initial_max_data ? `${Math.round(tp.initial_max_data / 1024)}KB` : "-";
    const idleMs = tp.max_idle_timeout ? `${tp.max_idle_timeout}ms` : "-";
    setProbe("quicpar", mismatch ? `协议穿帮：${mismatch}` : `${q.stackGuess} · ${q.ja4q} · 窗口 ${winKb}`, {
      tone: mismatch ? "bad" : "ok",
      why: `JA4Q: ${q.ja4q}\nQUIC ${q.quicVersion}${q.pqGroup ? " · PQ: " + q.pqGroup : ""}\nmax_idle_timeout: ${idleMs} · GREASE参数: ${q.hasGreaseParam ? "有" : "无"}\n参数序: ${(q.paramOrder || []).join(",")}`
    });
  }

  // (23) JS Engine JIT warm-up speedup ratio (cold interpreter vs Maglev/TurboFan/FTL machine code)
  function probeJitWarm() {
    const wasmOk = typeof WebAssembly === "object" && typeof WebAssembly.compile === "function";
    try {
      const makeKernel = salt => {
        try {
          return new Function("n", "seed", `
            var x = (seed ^ ${salt}) | 0, f = (seed & 255) * 0.125 + 1.0;
            var a0 = 1, a1 = 2, a2 = 3, a3 = 5;
            for (var i = 0; i < n; i++) {
              x = (Math.imul(x, 1664525) + 1013904223 + i) | 0;
              f = f * 0.9999847412109375 + ((x & 1023) * 0.0009765625);
              var t = (a0 + a1 + (x & 7)) | 0;
              a0 = a1; a1 = a2; a2 = a3; a3 = t;
            }
            return (x ^ a3 ^ (f | 0)) | 0;
          `);
        } catch (e) {
          return (n, seed) => {
            let x = (seed ^ salt) | 0, f = (seed & 255) * 0.125 + 1.0, a0 = 1, a1 = 2, a2 = 3, a3 = 5;
            for (let i = 0; i < n; i++) {
              x = (Math.imul(x, 1664525) + 1013904223 + i) | 0;
              f = f * 0.9999847412109375 + ((x & 1023) * 0.0009765625);
              const t = (a0 + a1 + (x & 7)) | 0;
              a0 = a1; a1 = a2; a2 = a3; a3 = t;
            }
            return (x ^ a3 ^ (f | 0)) | 0;
          };
        }
      };
      const coldFns = Array.from({ length: 24 }, (_, k) => makeKernel(0x9e3779b9 ^ (k * 7919)));
      let sink = 0;
      const t0 = performance.now();
      for (let k = 0; k < 24; k++) sink ^= coldFns[k](160, k + 1);
      const coldMs = Math.max(0.02, performance.now() - t0);

      const hotFn = coldFns[0];
      for (let w = 0; w < 140; w++) sink ^= hotFn(180, w);

      const t1 = performance.now();
      for (let h = 0; h < 240; h++) sink ^= hotFn(160, h + (sink & 3));
      const hotRawMs = Math.max(0.02, performance.now() - t1);
      const hotNormMs = hotRawMs / 10;
      const ratio = +(coldMs / Math.max(0.005, hotNormMs)).toFixed(2);
      R.jitWarm = { ratio, coldMs: +coldMs.toFixed(2), hotNormMs: +hotNormMs.toFixed(3), wasmOk, sink };

      if (!wasmOk) {
        setProbe("jitwarm", `JIT / WebAssembly 已被强制禁用（加速比 ${ratio}x · 锁定模式或 --jitless 沙箱）`, { tone: "warn" });
      } else if (R.coarseTimer && hotRawMs <= 1.2) {
        setProbe("jitwarm", `JIT 机器码正常 · WASM 就绪（防指纹粗化时钟限制微秒级加速比读数）`, { tone: "ok" });
      } else {
        const jitNote = ratio >= 1.8 ? "多级 JIT 编译加速正常" : "冷热耗时接近（极速核或轻量解释）";
        setProbe("jitwarm", `加速比 ${ratio}x（冷态 ${coldMs.toFixed(2)}ms → 热态等效 ${hotNormMs.toFixed(2)}ms · ${jitNote}）`, {
          tone: ratio >= 1.5 ? "ok" : "neutral"
        });
      }
    } catch (e) {
      setNA("jitwarm", "JIT 基准测试受限");
    }
  }

  // (24) WebGL highp shader ALU mantissa fingerprint & hardware compressed-texture cross-check
  async function probeGpuFp() {
    R.gpuTexConflict = "";
    let gl = null, lose = null;
    try {
      const c = document.createElement("canvas");
      c.width = 16;
      c.height = 16;
      gl = c.getContext("webgl2", { antialias: false, depth: false }) || c.getContext("webgl", { antialias: false, depth: false });
      if (!gl) return setNA("gpufp", "WebGL 不可用");
      lose = gl.getExtension("WEBGL_lose_context");

      const vs = gl.createShader(gl.VERTEX_SHADER);
      gl.shaderSource(vs, "attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}");
      gl.compileShader(vs);
      const fs = gl.createShader(gl.FRAGMENT_SHADER);
      gl.shaderSource(fs, `precision highp float;
        void main(){
          float u = gl_FragCoord.x * 0.137 + gl_FragCoord.y * 0.293;
          float a = fract(sin(u * 12.9898) * 43758.5453);
          float b = fract(exp2(u * 0.731) * 19.19);
          float c = fract(atan(u + 0.123, 0.777) * 31.4159);
          float d = fract(inversesqrt(u + 1.01) * 65537.0);
          gl_FragColor = vec4(a, b, c, d);
        }`);
      gl.compileShader(fs);
      const prog = gl.createProgram();
      gl.attachShader(prog, vs);
      gl.attachShader(prog, fs);
      gl.linkProgram(prog);
      gl.useProgram(prog);
      const buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
      const loc = gl.getAttribLocation(prog, "p");
      gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      const px = new Uint8Array(16 * 16 * 4);
      gl.readPixels(0, 0, 16, 16, gl.RGBA, gl.UNSIGNED_BYTE, px);

      const exts = gl.getSupportedExtensions() || [];
      const hasAstc = exts.some(e => /compressed_texture_astc/i.test(e));
      const hasS3tc = exts.some(e => /compressed_texture_s3tc\b/i.test(e));
      const hasBptc = exts.some(e => /texture_compression_bptc/i.test(e));
      const hasEtc = exts.some(e => /compressed_texture_etc\b/i.test(e));
      const hasRgtc = exts.some(e => /texture_compression_rgtc/i.test(e));
      const hasPvrtc = exts.some(e => /compressed_texture_pvrtc/i.test(e));
      const prec = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);
      const texTags = [hasAstc && "ASTC", hasS3tc && "S3TC", hasBptc && "BPTC", hasEtc && "ETC2", hasRgtc && "RGTC", hasPvrtc && "PVRTC"].filter(Boolean);

      const aluHash = shortHash(await sha256(Array.from(px).join(",")));
      const gpuStr = `${R.gpuDiscrete || ""} ${R.gpuRaw || ""}`;
      let conflict = "";
      if (!R.gpuSoft && /Apple M\d|Apple A\d+|Apple GPU/i.test(gpuStr) && !hasAstc) {
        conflict = "自报 Apple 自研芯片 GPU，但缺失硬件必有的 ASTC 压缩纹理支持（疑似 x86 桌面显卡改名伪装）";
      } else if (!R.gpuSoft && /NVIDIA GeForce|Quadro|Radeon RX/i.test(gpuStr) && hasAstc && !hasS3tc) {
        conflict = `自报桌面独显 (${cleanGpuName(R.gpuRaw)})，但仅支持移动端 ASTC 却无 S3TC 纹理（疑似 ARM/移动容器改名伪装）`;
      }
      R.gpuTexConflict = conflict;
      R.gpuAluHash = aluHash;
      setProbe("gpufp", conflict ? `架构穿帮：${conflict}` : `ALU 尾数 ${aluHash} · 硬件纹理 [${texTags.join("/") || "无"}]`, {
        tone: conflict ? "bad" : "ok",
        why: `highp float 精度: 2^-${prec?.precision ?? "?"} (范围 -2^${prec?.rangeMin ?? "?"}..2^${prec?.rangeMax ?? "?"})\n压缩纹理族: ${texTags.join(", ") || "无"}`
      });
    } catch (e) {
      setNA("gpufp", "GPU 着色器采样受限");
    } finally {
      try { lose && lose.loseContext(); } catch (e) {}
    }
  }

  // (25) 4th & 5th Execution Realms: SharedWorker & ServiceWorker cross-verification
  async function probeSwRealm() {
    R.swRealmDiff = [];
    const swUrl = new URL("./sw-probe.js", location.href).href;
    const norm = s => String(s || "").replace(/\s+/g, " ").trim();

    const pShared = (async () => {
      if (typeof SharedWorker !== "function") return null;
      try {
        const sw = new SharedWorker(swUrl);
        sw.port.start();
        const res = await within(new Promise(r => {
          sw.port.onmessage = ev => r(ev.data);
          sw.onerror = () => r(null);
          sw.port.postMessage("snap");
        }), 1800, null);
        try { sw.port.close(); } catch (e) {}
        return res ? ["SharedWorker", res] : null;
      } catch (e) { return null; }
    })();

    const pService = (async () => {
      if (!window.isSecureContext || !navigator.serviceWorker?.register) return null;
      let reg = null;
      try {
        reg = await within(navigator.serviceWorker.register(swUrl, { scope: "./__wp_sw_probe__/" }), 1800, null);
        if (!reg) return null;
        const worker = reg.installing || reg.waiting || reg.active;
        if (!worker) return null;
        const res = await within(new Promise(r => {
          const mc = new MessageChannel();
          mc.port1.onmessage = ev => r(ev.data);
          try { worker.postMessage("snap", [mc.port2]); } catch (e) { r(null); }
        }), 1600, null);
        return res ? ["ServiceWorker", res] : null;
      } catch (e) {
        return null;
      } finally {
        try { if (reg) await reg.unregister(); } catch (e) {}
      }
    })();

    const realms = (await Promise.all([pShared, pService])).filter(Boolean);
    if (!realms.length) {
      return setNA("swrealm", "当前容器未启用 SharedWorker / ServiceWorker");
    }

    const diffs = [];
    const mainLang = (navigator.language || "").split("-")[0].toLowerCase();
    const mainGpu = norm(R.gpuRaw || "");
    for (const [rName, d] of realms) {
      if (d.ua && d.ua !== navigator.userAgent) diffs.push(`${rName}.UA`);
      if (d.plat && d.plat !== navigator.platform) diffs.push(`${rName}.platform`);
      if (d.hc && navigator.hardwareConcurrency && d.hc !== navigator.hardwareConcurrency) diffs.push(`${rName}.CPU核数(${d.hc}≠${navigator.hardwareConcurrency})`);
      if (d.tz && R.tz && d.tz !== R.tz) diffs.push(`${rName}.时区(${d.tz}≠${R.tz})`);
      if (d.lang && mainLang && d.lang.split("-")[0].toLowerCase() !== mainLang) diffs.push(`${rName}.语言(${d.lang})`);
      if (d.gpu && mainGpu && norm(d.gpu) !== mainGpu) diffs.push(`${rName}.GPU`);
    }
    R.swRealmDiff = diffs;
    const names = realms.map(([n]) => n).join(" + ");
    setProbe("swrealm", diffs.length
      ? `跨线程穿帮：${diffs.join("、")} 与主线程不一致`
      : `${names} 与主线程全量核对一致（已即采即销零残留）`,
    {
      tone: diffs.length ? "bad" : "ok",
      why: realms.map(([n, d]) => `${n}: plat=${d.plat} · hc=${d.hc} · tz=${d.tz} · lang=${d.lang}`).join("\n")
    });
  }

  // (26) Behavioral Biometrics Dynamics: Mouse velocity CV & jerk, trackpad vs discrete wheel, keystroke dwell
  function probeBioDyn() {
    R.bioSynthKey = false;
    R.bioConstVel = false;
    const pts = INPUT_LOG.pts || [];
    const wheels = INPUT_LOG.wheelDeltas || [];
    const dwells = INPUT_LOG.dwells || [];
    const parts = [];
    let tone = "neutral";

    if (pts.length >= 8) {
      const vels = [];
      for (let i = 1; i < pts.length; i++) {
        const dt = pts[i].t - pts[i - 1].t;
        if (dt >= 2 && dt <= 250) {
          vels.push(Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y) / dt);
        }
      }
      if (vels.length >= 6) {
        const meanV = vels.reduce((a, b) => a + b, 0) / vels.length;
        const stdV = Math.sqrt(vels.reduce((s, v) => s + (v - meanV) ** 2, 0) / vels.length);
        const cv = meanV > 0.01 ? +(stdV / meanV).toFixed(2) : 0;
        const constVel = meanV > 0.15 && cv < 0.08 && vels.length >= 12;
        R.bioConstVel = constVel;
        parts.push(constVel ? `鼠标匀速机械插值 (速度CV=${cv})` : `鼠标速度变异 CV=${cv} (真人加减速)`);
        tone = constVel ? "warn" : "ok";
      }
    }

    if (wheels.length >= 2) {
      const fine = wheels.some(w => w.mode === 0 && w.dy > 0 && (w.dy < 40 || !Number.isInteger(w.dy)));
      const discrete = wheels.every(w => w.mode === 1 || (w.dy >= 80 && (Math.round(w.dy) % 100 === 0 || Math.round(w.dy) % 120 === 0)));
      parts.push(fine ? "触控板连续像素流" : discrete ? "物理滚轮离散步进" : `滚轮采样 ${wheels.length} 次`);
      if (tone === "neutral") tone = "ok";
    }

    if (dwells.length >= 1) {
      const meanDw = dwells.reduce((a, b) => a + b, 0) / dwells.length;
      if (dwells.length >= 3 && meanDw < 1.5) {
        R.bioSynthKey = true;
        parts.push(`异常按键驻留 ${meanDw.toFixed(2)}ms (瞬时脚本注入！)`);
        tone = "bad";
      } else {
        parts.push(`键驻留均值 ${Math.round(meanDw)}ms (${dwells.length} 键)`);
        if (tone === "neutral") tone = "ok";
      }
    }

    if (!parts.length) {
      setProbe("biodyn", "扫描期无交互输入（移动鼠标/滚动/按键后重测可采动力学特征）", { tone: "neutral" });
    } else {
      setProbe("biodyn", parts.join(" · "), { tone });
    }
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

    // 4. Manual Localhost Proxy & Anti-Detect Browser Control Port Self-Test (zero unsolicited LNA prompt)
    const LOCAL_PORTS = [
      [7890, "Clash / Mihomo 混合口"],
      [7891, "Clash SOCKS/HTTP"],
      [9090, "Clash / Mihomo API"],
      [10808, "v2rayN / Xray 代理口"],
      [1080, "SOCKS5 本地口"],
      [2080, "Sing-box / NekoBox"],
      [50325, "AdsPower 本地 API"],
      [54345, "比特浏览器 API"],
      [35000, "Multilogin 控制口"],
      [9222, "Chrome CDP 调试口"]
    ];
    setProbe("localport", `<button type="button" id="btnRunLocalPort" class="py-0.5 px-2 rounded bg-blue-50 text-blue-700 hover:bg-blue-100 font-sans font-medium text-[11px] dark:bg-blue-500/15 dark:text-blue-400">点击自检 10 个本机代理/指纹口</button>`, {
      html: true, rawText: "未触发手动本机端口自检"
    });
    const btnLp = $("#btnRunLocalPort");
    if (btnLp) {
      btnLp.onclick = async ev => {
        ev.stopPropagation();
        btnLp.disabled = true;
        btnLp.textContent = "正在探测 127.0.0.1 常用端口…";
        const hits = await Promise.all(LOCAL_PORTS.map(async ([port, label]) => {
          try {
            await fetch(`http://127.0.0.1:${port}/`, {
              mode: "no-cors",
              cache: "no-store",
              credentials: "omit",
              referrerPolicy: "no-referrer",
              signal: AbortSignal.timeout(1100)
            });
            return `${port} (${label})`;
          } catch (e) {
            return null;
          }
        }));
        const openList = hits.filter(Boolean);
        setProbe("localport", openList.length
          ? `检出 ${openList.length} 个本机开放服务：${openList.join("、")}`
          : `10 个常见代理/指纹浏览器端口均未对网页暴露（或已被浏览器本地网络策略拦截）`,
        {
          tone: openList.length ? "warn" : "ok",
          why: `检测范围: ${LOCAL_PORTS.map(([p, l]) => `${p}/${l}`).join(" · ")}`
        });
      };
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
        "终极根治：在代理链路最末端挂载真实同构系统住宅节点（如真 Mac mini / Windows 软路由出口，或原生住宅 SOCKS5 落地），或强制走 HTTP/3 (QUIC over UDP) 隐藏内核 TCP SYN 选项。",
        "若提示「中间层注入代理转发头」：TLS 已在本站终止，Via / Forwarded / X-Forwarded-For 只能由解密 HTTPS 的中间人（企业网关、杀软 HTTPS 扫描、抓包工具或 Cloudflare Worker 反代）添加——请关闭杀软的 HTTPS 扫描 / 抓包代理，或改用不改写请求头的透明隧道。"
      ],
      synspoof: [
        "服务端 AF_PACKET 同时比对了首包 SYN 与后续 TLS ClientHello 数据包的 IPv4 DF 分片位、IPID 递增规律及 TCP Timestamp (TSval) 内核节拍频率 (Hz)。",
        "若提示「无状态 SYN 改包」：说明代理机使用了 osfuscate 等仅篡改首个 SYN 包的工具，但后续数据包恢复了 Linux 原始内核时钟，被跨包连续性校验一眼拆穿。",
        "若提示「微脉冲多路复用粘包」：说明代理启用了 Mux / smux / yamux 或高抖动隧道合并转发；高敏感业务建议关闭代理客户端的 Mux 多路复用选项。"
      ],
      reality: [
        "服务端主动反向连接你当前出口 IP 的 :443 端口进行 TLS 证书归属验真：真实家庭宽带光猫在公网侧通常关闭 :443，绝不会挂载大厂官网证书。",
        "若检出「非官方 ASN 却返回 Microsoft / Apple / Yahoo / Amazon 等大厂证书」，这是 VLESS-Reality 借用他人域名证书的铁证——严苛风控一旦反向回探，100% 实锤代理节点！",
        "修复建议：将自建 Reality / TLS 节点监听端口迁离标准 :443，或在代理服务端配置 Outbound 链式转发至不开任何公网端口的纯净家宽落地 IP。",
        "端口回扫：服务端同时对出口 IP 并发 connect 17 个常见代理 / VPN / 远控 / 面板端口（1080、3128、8388、7890、10808、1194、22、3389、54321 等）。出口若开放 SOCKS / HTTP 代理或 Shadowsocks、OpenVPN 端口，等于直接告诉风控「这台机器就是代理服务器」——请用防火墙 / 安全组仅对自己的来源 IP 放行，并关闭 X-UI 等面板的公网监听。"
      ],
      rtt: [
        "原理（三维物理测距）：① 服务端测量 TCP 握手耗时（代理节点→本站物理距离）；② 浏览器测量 HTTP 往返耗时（你的电脑→代理节点→本站）；③ WebRTC 测量 STUN UDP 候选耗时。三者差值直接框定「你到代理节点」多绕的物理路程，无法靠改浏览器插件伪造。",
        "有效解法：① 缩短第一跳物理距离——亚洲用户优先选用日本/新加坡/香港 IEPL/IPLC 专线（电脑→节点仅 +8~20ms，落入正常 Wi-Fi 抖动阈值内）；② 若必须用欧美住宅 IP，直接在同城云桌面（如美西 Mac/Win 远程主机）内打开浏览器，使浏览器与出口物理同地，实现 0ms 中转差！",
        "光速违例：浏览器还会对 AWS 全球 18 个区域测量热连接往返。任何信号都不可能快于光纤中的光速（往返约 距离/100 ms），若到某区域的往返低于「出口 IP 登记地 → 该区域」的物理下限，说明这条流量根本没走当前出口（规则分流直连），或出口 IP 是登记在 A 洲却在 B 洲广播的「广播 IP」。修复：改用全局 / TUN 模式，并选择 RIR 注册国与实际机房一致的原生 IP。"
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
        "建议打开无扩展的干净浏览器 Profile 测试；切勿在普通浏览器安装「Canvas Defender / User-Agent Switcher」等浅层插件（越装越容易被直接判定为黑产环境）。",
        "v7.4 新增的跨层核验更难绕过：① CSS 媒体查询（device-width / resolution）由渲染引擎计算，只改 JS screen 属性必然矛盾；② 夏令时与 2005/2015 历史时区规则由 ICU 计算，只 Hook getTimezoneOffset 固定值会在冬夏切换露馅；③ FontFace local() 直接走系统字体服务，只 Hook Canvas measureText 的字体伪装会被反证；④ Accept-Language 改写须保持 q 权重递减且语种与 navigator.languages 同源。"
      ],
      fpb: [
        "指纹浏览器三大常见死穴：① 只改主线程忘了改 Web Worker；② 虚报新版 Chrome 但底层 Chromium 内核缺失新版 JS/CSS 特性；③ Windows 机器伪装成 Mac 但显卡渲染器仍暴露 Direct3D。",
        "修复建议：升级指纹浏览器到最新内核版本，并保持「真实宿主机系统 = Profile 伪装系统」。",
        "WebAssembly 特性矩阵（GC / 尾调用 / Relaxed SIMD / JSPI 等）是内核编译期决定的，无法通过 JS 注入伪造；本地字体 local() 旁路则直接反映宿主系统字库——两者都与 UA 自报版本 / 系统对不上时，说明内核或宿主机与伪装不符。"
      ],
      ua: [
        "请关闭任何改 User-Agent 的插件或开发者工具设备模拟模式，保持 HTTP 请求头、Sec-CH-UA-Platform 与显卡驱动平台三者自然一致。",
        "冒充手机时，触控点数、主指针精度 (pointer: coarse)、悬停能力、ontouchstart、屏幕短边与 GPU 型号（Adreno / Mali / Apple GPU）必须同时成立；DevTools 设备模拟无法改变桌面显卡型号，需真机或云手机。",
        "Sec-CH-UA 的 GREASE 伪品牌由 Chromium 主版本号按固定算法生成（如 Chrome 136 为 \"Not.A/Brand\";v=\"99\"），vendor / productSub / eval.toString 长度 / appVersion 也必须与所报浏览器一致——手工拼接的 Client Hints 或改 UA 插件很难全部对齐，请勿跨浏览器内核伪装。"
      ],
      bot: [
        "当前浏览器暴露了 navigator.webdriver、CDP 调试协议附着或自动化框架注入标记（Selenium / Playwright / Puppeteer）。",
        "CDP 附着检测：只要 DevTools Protocol 的 Runtime 域被启用（开发者工具打开、Puppeteer / Playwright 默认行为），控制台序列化就会触发探针；手动排查时请关闭开发者工具后重测。",
        "无头窗口：outerWidth/outerHeight 为 0 或与视口完全相同属于无头 / Kiosk 特征；合成事件 (isTrusted=false) 则直接证明页面交互由脚本 dispatchEvent 伪造。",
        "大厂同款清单：BotD / PerimeterX / Akamai / TikTok 会扫描 60 余个框架全局变量（$cdc_、__nightmare、Cypress、%hammerhead%…）、Node / Electron 宿主、ActiveText 纯红与破损图 0×0 等无头渲染特征，以及 stealth 插件留下的 webdriver=undefined、伪造 window.chrome、srcdoc iframe 代理与 Proxy 错误栈——打补丁只会留下更多破绽，建议直接使用真实有界面浏览器。",
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
    if (!ipCC && !R.finished) {
      out.syslang = { level: "info", summary: "等待出口国家与底层字库/离线语音交叉核对…" };
    } else if (!sys || !ipCC) {
      out.syslang = { level: "ok", summary: `${R.dev?.os || "当前系统"} 未暴露与出口矛盾的独有区域字库或键位` };
    } else if (!sys.cc.length || sys.cc.includes(ipCC)) {
      out.syslang = { level: "ok", summary: `系统底层字库、离线语音包与 ${R.kbd || "标准"} 键位未见跨区异常` };
    } else {
      const leakedCountries = sys.cc.map(countryName).join(" / ");
      const srcNames = sys.from.map(k => ({ fonts: "系统字库", voices: "离线语音包", kbd: "物理键盘布局" })[k] || k).join("、");
      out.syslang = { level: "warn", summary: `${srcNames}暴露系统装有 ${leakedCountries} 环境，与 ${ipCountry} 出口不一致` };
    }
    if (R.tzNameLeak && out.syslang.level !== "warn") {
      out.syslang = { level: "warn", summary: R.tzNameLeak };
    }

    // 4. dns: Recursive DNS Resolver & EDNS Client Subnet vs Exit IP
    const ecsMismatch = R.ecsIp && R.ip && netPrefix(R.ecsIp) && netPrefix(R.ip) && netPrefix(R.ecsIp) !== netPrefix(R.ip);
    if (!R.dnsCC) {
      out.dns = { level: "info", summary: R.finished ? "DNS 递归探针未返回结果或被当前网络策略阻断" : "正在发起随机子域名递归 DNS 解析探测…" };
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
    const sp = analyzeExitSplit();

    if (!R.exitsDone) {
      out.split = { level: "info", summary: "正在并发比对国内外与 AI 平台分流出口…" };
    } else if (sp.state === "cn-leak" && cnIp) {
      out.split = { level: "bad", summary: `规则分流直接露底：本站走 ${ipCountry}，但大陆测速探针直连暴露真实国内宽带 (${cnIp.ip} · ${cnIp.label})！` };
    } else if (sp.state === "multi-country" || sp.state === "multi-prefix" || sp.state === "dual-stack-mismatch") {
      const detail = sp.validExits.map(([k, v]) => `${({ ex_self: "本站", ex_cn: "国内", ex_intl: "国际", ex_gpt: "ChatGPT", ex_claude: "Claude", ex_cf: "CF" })[k] || k}:${v.cc || "?"}`).join(" / ");
      out.split = {
        level: "warn",
        summary: sp.state === "multi-country"
          ? `检测到跨国多路分流：并发请求落在了 ${sp.distinctCount} 个不同国家/地区 (${detail})`
          : `检测到多路代理分流：并发请求落在了不同运营商/异构出口网段 (${detail})`
      };
    } else {
      out.split = {
        level: "ok",
        summary: sp.dualStackAligned || sp.cgnatAligned
          ? `全局同源一致：所有可达目标均走同一 ${ipCountry} 运营商出口池（双栈 / CGNAT 正常选路）`
          : `全局路由一致：所有测试目标均稳定走同一 ${ipCountry} 出口网段`
      };
    }

    // 6. conn: Passive TCP/TLS Stack vs Claimed OS
    const tcp = R.srv?.packet?.tcp;
    const tls = R.srv?.packet?.tlsClientHello || R.srv?.packet?.tls;
    const uaOs = R.dev?.os || "";
    if (!tcp) {
      out.conn = { level: "info", summary: !R.srv && !R.finished ? "正在嗅探服务端 TCP SYN 首包与 TLS 握手栈…" : "当前连接复用了既有会话，点击「重新检测」可触发全新 SYN 握手抓包" };
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
      const cellularMtuOk = isCellularNativeLink(uaOs, osMismatch) && tcp.mtu >= 1360 && tcp.mtu <= 1476;

      if (osMismatch) {
        const tcpHuman = ({ windows: "Windows", apple: "macOS / iOS", linux: "Linux / Android" })[tcpFam] || tcp.osGuess || tcpFam;
        out.conn = { level: "bad", summary: `底层协议栈穿帮：UA 声称你在用 ${uaOs}，但替你发起 TCP 连接的机器却是 ${tcpHuman}（典型代理服务器代发连接特征）` };
      } else if (noGrease) {
        out.conn = { level: "bad", summary: `TLS 握手异常：声称为 Chromium 浏览器但缺失 GREASE 扩展，流量疑似被中间人解密重签或非原生浏览器发包` };
      } else if (tun && !["ethernet", "pppoe"].includes(tun) && !cellularMtuOk) {
        out.conn = { level: "warn", summary: `TCP 协议栈系统吻合，但链路 MTU=${tcp.mtu} 暴露了 VPN / 虚拟网卡隧道封装特征 (${tun})` };
      } else {
        out.conn = {
          level: "ok",
          summary: cellularMtuOk
            ? `TCP 初始 TTL=${tcp.initialTtl} 与 TLS 指纹吻合 ${uaOs || "端侧"} 原生栈，MTU=${tcp.mtu} 符合 4G/5G 蜂窝移动网络原生承载封装`
            : `TCP 初始 TTL=${tcp.initialTtl}、窗口选项与 TLS 指纹均与 ${uaOs || "自报系统"} 原生协议栈吻合`
        };
      }
    }

    // 6b. conn overlay: HTTP/2 Akamai raw frame, QUIC Initial JA4Q, TLS static extension order, or HTTPS middlebox headers
    if (R.h2Mismatch && out.conn?.level !== "bad") {
      out.conn = { level: "bad", summary: `HTTP/2 原始帧穿帮：${R.h2Mismatch}（仅靠改 UA 或 TLS 无法伪造 HTTP/2 SETTINGS 与伪头部顺序）` };
    } else if (R.quicStackMismatch && out.conn?.level !== "bad") {
      out.conn = { level: "bad", summary: `QUIC Initial 协议穿帮：${R.quicStackMismatch}` };
    } else if (R.tlsStaticPerm && out.conn?.level !== "bad") {
      out.conn = { level: "bad", summary: `TLS 扩展排列死板：自称现代 Chromium，但连续独立握手的扩展顺序 100% 静态不变（典型 uTLS / 静态指纹模板特征）` };
    } else if ((R.proxyHdrHits || []).length && out.conn?.level !== "bad") {
      out.conn = { level: "warn", summary: `TLS 握手后的 HTTP 请求被中间层注入代理转发头（${R.proxyHdrHits.join(" · ")}），疑似 HTTPS 解密代理 / 企业网关 / 杀软 Web 防护 / CF Worker 反代` };
    }

    // 7. synspoof: IP DF/IPID Continuity, TCP Timestamp Hz & Mux Coalescing
    const mux = R.muxBurst;
    // Only flag DF=0 as an OS header contradiction when the wire TCP SYN itself is NOT already a
    // genuine Linux stack (`osFamily === "linux"` or `IPID=0`), avoiding false positives when an
    // upstream ISP / cloud SDN / CGNAT router clears the outer IPv4 DF bit in transit.
    const linuxClaimDfZero = tcp
      && tcp.df === false
      && tcp.osFamily !== "linux"
      && !(tcp.synIpId === 0 && tcp.helloIpId === 0)
      && /^(Linux|Android|HarmonyOS)$/.test(uaOs);
    if (!tcp && !mux) {
      out.synspoof = { level: "info", summary: "等待底层 IP/TCP 跨包时钟与微脉冲粘包核验…" };
    } else if (tcp?.synSpoofSuspect) {
      out.synspoof = { level: "bad", summary: `抓获无状态 SYN 改包：首包与后续数据包 TSval 时钟节拍 (${tcp.tsHz ?? "突变"}Hz) 或 IPID 序列前后断裂！` };
    } else if (linuxClaimDfZero) {
      out.synspoof = { level: "warn", summary: `IP 包头矛盾：自报 ${uaOs} 系统（默认强制 DF=1），但网卡实测首包 DF=0 允许分片` };
    } else if (isMuxTunnelSuspect(mux)) {
      out.synspoof = { level: "warn", summary: `检出隧道粘包合并：6 组微脉冲到达服务端时出现 ${mux.coalescedPairs} 对粘包合并，疑似经过 Mux 多路复用代理` };
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

    // 8b. reality overlay: live proxy / VPN / remote-control port back-scan of the visitor's own egress
    const pts = R.intel?.ports;
    if (pts?.probed && !pts.synProxyLikely && R.intel?.isSelfEgress !== false) {
      const hardPorts = [...(pts.proxyOpen || []), ...(pts.vpnOpen || [])];
      const softPorts = [...(pts.remoteOpen || []), ...(pts.panelOpen || [])];
      const desc = (pts.open || []).filter(o => o.kind !== "web").map(o => `${o.port}/${o.svc}`).slice(0, 5).join("、");
      if (hardPorts.length && out.reality.level !== "bad") {
        out.reality = { level: "bad", summary: `出口实时回扫命中代理 / VPN 服务端口 (${desc})：当前出口本身就是一台代理或 VPN 服务器` };
      } else if (softPorts.length && out.reality.level === "ok" && R.netKind !== "dc") {
        out.reality = { level: "warn", summary: `出口自称非机房宽带，但公网开放远控 / 面板端口 (${desc})` };
      } else if (out.reality.level === "ok") {
        out.reality = { ...out.reality, summary: `${out.reality.summary} · ${desc ? `端口回扫：${desc}` : `${pts.scanned} 个代理/远控端口全部关闭`}` };
      }
    }

    // 9. rtt: 3D Physical Distance Triangulation (Browser HTTP vs Server TCP vs WebRTC STUN UDP + Geo Fiber Floor)
    if (!R.latDone || R.httpRtt == null) {
      out.rtt = { level: "info", summary: R.coarseTimer ? "浏览器开启了时钟降精度保护，无法精确测量毫秒级往返差" : "等待浏览器热连接、服务端握手与 UDP 候选三维测距…" };
    } else {
      const tcpMatchesDirect = R.srvTcpRtt != null && (R.httpRtt - R.srvTcpRtt) < 42 && !getLeakedWebrtcIps().length;
      const udpBypass = R.stunRttMs != null && (R.httpRtt - R.stunRttMs) >= 75 && !tcpMatchesDirect;
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

    // 9b. rtt overlay: multi-region speed-of-light violation or WebSocket Pong control-frame relay gap
    const geoRtt = analyzeRttGeo();
    if (geoRtt?.violation && out.rtt?.level !== "bad") {
      const v = geoRtt.violation;
      out.rtt = { level: "bad", summary: `光速违例：到 ${v.name} 往返仅 ${v.ms} ms，但出口 IP 登记地距其 ${v.km.toLocaleString()} km（光纤物理下限≈${v.floorMs} ms），该路流量未经出口或出口为跨洲广播 IP` };
    } else if (R.wsPingRtt != null && R.srvTcpRtt != null && (R.wsPingRtt - R.srvTcpRtt) >= 95 && out.rtt?.level !== "bad") {
      out.rtt = { level: "bad", summary: `底层控制帧测距抓获中转：服务端与出口握手仅 ${R.srvTcpRtt} ms，但 WebSocket Pong 控制帧需 ${R.wsPingRtt} ms（多绕 +${R.wsPingRtt - R.srvTcpRtt} ms 代理路程）` };
    } else if (geoRtt?.best && out.rtt?.level === "ok") {
      out.rtt = { ...out.rtt, summary: `${out.rtt.summary} · 全球测距最近 ${geoRtt.best.name} ${geoRtt.best.ms} ms` };
    }

    // 10. webrtc: WebRTC STUN Leak & IPv6 MAC Leak
    const rtcList = Array.isArray(R.rtc) ? R.rtc : [];
    const leakedRtc = getLeakedWebrtcIps();
    if ((!R.rtcDone || (rtcList.length && !R.ip)) && !R.finished) {
      out.webrtc = { level: "info", summary: "正在执行 STUN UDP 候选穿透与出口运营商同源核查…" };
    } else if (R.v6mac) {
      out.webrtc = { level: "bad", summary: `高危硬件泄漏：IPv6 地址中直接编码了物理网卡 MAC 地址 (${R.v6mac})！` };
    } else if (leakedRtc.length) {
      const leakCC = candidateCC(leakedRtc[0]);
      const reverseSplit = R.ipCC === "CN" && leakCC && leakCC !== "CN";
      out.webrtc = {
        level: "bad",
        summary: reverseSplit
          ? `分流导致 TCP/UDP 出口分裂：当前页面走大陆直连 (CN)，但 WebRTC STUN 走了海外代理 (${leakCC} · ${leakedRtc.join(", ")})`
          : `WebRTC UDP 穿透泄漏了与代理出口不同的真实公网 IP：${leakedRtc.join(", ")}`
      };
    } else {
      const sameNet = rtcList.length && rtcList.every(x => cleanIp(x) === cleanIp(R.ip) || netPrefix(x) === netPrefix(R.ip));
      out.webrtc = {
        level: "ok",
        summary: rtcList.length
          ? (sameNet
            ? `WebRTC 反射地址 (${rtcList[0]}) 与当前出口一致，未漏真实 IP`
            : `WebRTC 公网候选 (${rtcList[0]}) 属同国同运营商双栈/CGNAT 地址池，未跨网泄漏`)
          : "WebRTC 未暴露额外公网候选地址，局域网地址已隐藏"
      };
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
    if (!R.cpuBench && !R.gpuSoft && !R.finished) {
      out.hwvirt = { level: "info", summary: "正在采样 WASM SIMD 与 CPU 微基准抢占抖动…" };
    } else if (R.gpuSoft) {
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
      const jitterDesc = R.cpuBench?.timerQuantized ? "防指纹量化时钟保护正常" : `抢占抖动比 ${steal}x`;
      out.hwvirt = {
        level: "ok",
        summary: `物理硬件特征自然：WASM SIMD 正常${hwc != null ? ` · ${hwc}/4 项视频硬解芯片就绪` : ""} · ${jitterDesc}`
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
    if ((R.mqDiffs || []).length) tamperReasons.push(`CSS 媒体查询与 JS 屏幕读数矛盾 (${R.mqDiffs.join("；")})`);
    if (R.tzDstMismatch) tamperReasons.push(`夏令时 / 历史时区规则断裂 (${R.tzDstMismatch[0]})`);
    if ((R.clockInternalGap || 0) > 1000) tamperReasons.push(`Date 接口相互矛盾 ${R.clockInternalGap} ms（时间被部分 Hook）`);
    if ((R.fontLocalHidden || []).length) tamperReasons.push(`Canvas 字体探测被 Hook（local() 证明已安装 ${R.fontLocalHidden.slice(0, 2).join(" / ")}）`);
    if ((R.alIssues || []).length) tamperReasons.push(`Accept-Language 头被改写 (${R.alIssues[0]})`);
    if (R.intlDeepMismatch) tamperReasons.push(`Intl 多构造器默认区域分裂 (${R.intlDeepMismatch})`);
    const strongNewTamper = (R.mqDiffs || []).length > 0 || !!R.tzDstMismatch || (R.clockInternalGap || 0) > 1000 || (R.fontLocalHidden || []).length > 0 || !!R.intlDeepMismatch;

    if (!tamperReasons.length) {
      out.tamper = { level: "ok", summary: "52 项原生原型、HTTP 请求头、洁净 iframe 与像素回读均纯净无篡改痕迹" };
    } else {
      const severe = strongNewTamper || tamperReasons.length >= 2 || (R.lies || []).length >= 2 || (R.iframeDiffs || []).length > 0 || R.tzOff !== R.dateOff || (hdrUa && hdrUa !== navigator.userAgent);
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
    const wf = R.wasmFeat;
    if (wf && wf.simd) {
      const claimedFf = +((/Firefox\/(\d+)/.exec(navigator.userAgent) || [])[1] || 0);
      if (R.engine === "V8" && claimedChrome >= 121 && !wf.gc) fpbHits.push(`虚报 Chrome ${claimedChrome}，但 WebAssembly GC（Chromium 119+ 默认启用）不可用`);
      else if (R.engine === "V8" && claimedChrome >= 114 && !wf.tailCall) fpbHits.push(`虚报 Chrome ${claimedChrome}，但 WebAssembly 尾调用（Chromium 112+）不可用`);
      else if (R.engine === "SpiderMonkey" && claimedFf >= 122 && !wf.gc) fpbHits.push(`虚报 Firefox ${claimedFf}，但 WebAssembly GC（Firefox 120+）不可用`);
    }
    if (R.fontLocalOsConflict) fpbHits.push(`本地字体旁路：${R.fontLocalOsConflict}`);
    if (R.cpuArchConflict) fpbHits.push(`CPU 架构矛盾：${R.cpuArchConflict}`);
    if (R.sysFontConflict) fpbHits.push(R.sysFontConflict);
    if (R.glWorkerMismatch) fpbHits.push(`WebGL 跨线程穿帮：${R.glWorkerMismatch}`);
    if ((R.swRealmDiff || []).length) fpbHits.push(`Shared/ServiceWorker 跨界矛盾 (${R.swRealmDiff.join(", ")})`);
    if (R.ufragConflict) fpbHits.push(`WebRTC SDP 引擎矛盾：${R.ufragConflict}`);
    if (R.gpuTexConflict) fpbHits.push(`GPU 压缩纹理架构穿帮：${R.gpuTexConflict}`);
    if (R.stackFmtConflict) fpbHits.push(`调用栈引擎矛盾：${R.stackFmtConflict}`);
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
    if ((R.mobileHits || []).length >= 2) {
      uaMismatch.push(`自称移动设备但硬件与输入特征自相矛盾 (${R.mobileHits.slice(0, 3).join(" · ")})，典型 DevTools 设备模拟或改 UA 冒充`);
    }
    if ((R.greaseIssues || []).length) uaMismatch.push(`Sec-CH-UA 品牌伪造：${R.greaseIssues[0]}`);
    if ((R.navPropIssues || []).length) uaMismatch.push(`navigator 厂商属性矛盾：${R.navPropIssues.slice(0, 2).join("；")}`);
    out.ua = uaMismatch.length
      ? { level: "bad", summary: uaMismatch.join("；") }
      : { level: "ok", summary: `User-Agent、Client Hints 与硬件平台 (${R.osLabel || "未知"}) 三方一致` };

    // 19. bot: Automation & Headless Browser (WebDriver hooks, CDP attach, headless window frame, synthetic input events)
    const botBad = [...(R.botHits || [])];
    if ((R.inputUntrusted || 0) > 0) botBad.push(`${R.inputUntrusted} 个 isTrusted=false 合成输入事件`);
    if (R.inputCdpCoord) botBad.push(`${R.inputCdpCoord} 个鼠标事件坐标呈 CDP 派发特征`);
    if ((R.stealthHits || []).length) botBad.push(`隐身补丁残留 ${R.stealthHits.length} 处（${R.stealthHits[0]}）`);
    if ((R.jsEnvBad || []).length) botBad.push(`非浏览器宿主 ${R.jsEnvBad.join("/")}`);
    if (R.bioSynthKey) botBad.push("按键驻留 <1.5ms（脚本瞬时派发按键特征）");
    const botWarn = [];
    if ((R.headlessSoft || []).length && !(R.headlessHits || []).length) botWarn.push(`无头弱信号：${R.headlessSoft[0]}`);
    if (R.cdpHit) botWarn.push("CDP Runtime 调试协议已附着（开发者工具打开或被 Puppeteer / Playwright 控制）");
    if (R.popupDisabled) botWarn.push("无手势弹窗拦截已关闭 (--disable-popup-blocking 或站点放行)");
    if (R.winHeadless) botWarn.push("无头窗口尺寸特征（浏览器外框为 0 或窗口大于屏幕）");
    if (R.inputStraight != null && R.inputStraight >= 0.9) botWarn.push(`鼠标轨迹 ${Math.round(R.inputStraight * 100)}% 为机械直线`);
    if (R.bioConstVel) botWarn.push("鼠标移动呈恒定匀速插值（缺少真人加减速动力学特征）");
    out.bot = botBad.length
      ? { level: "bad", summary: `检出自动化控制框架特征：${[...botBad, ...botWarn].join(" · ")}` }
      : botWarn.length
      ? { level: "warn", summary: `存在调试 / 无头环境迹象：${botWarn.join(" · ")}` }
      : { level: "ok", summary: "未发现 WebDriver、CDP 附着、无头窗口外框或合成输入事件" };

    // 20. fp: Cross-Site Tracking Resistance & Partial Storage Wipe / ETag Resurrection
    const protectedFp = ["brave", "rfp", "fpp", "atfp"].includes(R.shieldKind);
    const lsCleared = !R.traceSurvived || !R.traceSurvived.includes("LocalStorage");
    const cacheResurrected = R.finished && lsCleared && (!!R.etag?.seen || (R.traceSurvived || []).length > 0);
    R.cacheResurrected = cacheResurrected;

    if (!R.fpId && !R.finished) {
      out.fp = { level: "info", summary: "正在校验缓存 ETag、多重本地留痕与跨站硬件码…" };
    } else if (cacheResurrected) {
      out.fp = {
        level: "bad",
        summary: R.etag?.seen
          ? `防关联隔离穿帮：已清空本地存储试图伪装新访客，但浏览器 HTTP ETag 缓存 (${R.etag.id.slice(0, 8)}) 仍直接认出老身份！`
          : `防关联残留复活：LocalStorage 虽已清除，但 ${R.traceSurvived.join(" / ")} 仍保留旧标记 (${R.traceTag})！`
      };
    } else if (protectedFp) {
      out.fp = { level: "ok", summary: `已受 ${R.shieldLabel} 保护，跨站静态指纹已被动态打散` };
    } else if (R.etag?.seen || (R.traceSurvived || []).length > 1) {
      out.fp = currentScene === "privacy"
        ? { level: "bad", summary: `无防指纹保护且已被缓存 ETag / 多重存储跨会话锁定 (硬件码 ${R.hwId})` }
        : { level: "info", summary: `同环境持久化会话正常：当前独立窗口保留了会话缓存与固定硬件码 (${R.hwId})，多账号防关联请在不同环境窗口间对比硬件码` };
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

  const SHORT_CHECK_TITLE = {
    tz: "系统时区",
    lang: "浏览器语言",
    syslang: "底层语种",
    dns: "DNS 归属",
    split: "国内外分流",
    conn: "TCP 协议栈",
    synspoof: "TSval 与粘包",
    reality: ":443 与端口回扫",
    rtt: "物理测距",
    webrtc: "WebRTC 泄漏",
    dc: "机房/家宽属性",
    lease: "伪家宽与租赁",
    reputation: "黑名单与脏邻居",
    subpixel: "光栅化与控件",
    hwvirt: "虚拟化与硬解",
    tamper: "环境篡改检测",
    fpb: "指纹浏览器矛盾",
    ua: "UA 与高熵头",
    bot: "自动化痕迹",
    fp: "缓存与防关联"
  };

  function shortTzCity(tz) {
    if (!tz) return "未知";
    const seg = String(tz).split("/").pop().replace(/_/g, " ");
    return seg.length > 13 ? seg.slice(0, 12) + "…" : seg;
  }

  function getVisualConflict(id, res) {
    const lv = res?.level || "info";
    const ipTz = R.srv?.geo?.timezone || R.intel?.consensus?.timezone || "";
    const tcp = R.srv?.packet?.tcp;
    const uaOs = R.dev?.os || "端侧";
    const tcpHuman = tcp ? (({ windows: "Windows", apple: "macOS", linux: "Linux" })[tcp.osFamily || tcp.osGuess] || tcp.osGuess || "未知") : "未知";

    if (lv === "info") return { single: "待核验" };
    if (lv === "ok") {
      switch (id) {
        case "tz": return { single: `${shortTzCity(R.tz)} 对齐` };
        case "lang": return { single: `${R.langs?.[0] || "语言"} 吻合` };
        case "dns": return { single: `${R.dnsCC ? flagEmoji(R.dnsCC) + " " + R.dnsCC : "同国"} 无泄漏` };
        case "split": return { single: "全局同出口" };
        case "conn": return { single: `${uaOs} 栈吻合` };
        case "rtt": return { single: `${R.httpRtt ?? "--"}ms 正常` };
        case "dc": return { single: R.netKind === "mobile" ? "蜂窝移动/ISP" : "原生宽带/ISP" };
        case "lease": return { single: "原生直配段" };
        case "reputation": return { single: `纯净 ${R.intel?.purity?.score ?? "--"}` };
        default: return { single: "通过" };
      }
    }

    // Issue states (bad / warn): return crisp A ≠ B visual pairs!
    switch (id) {
      case "tz":
        return { left: shortTzCity(R.tz), op: "≠", right: ipTz ? shortTzCity(ipTz) : (R.ipCC || "出口") };
      case "lang":
        return { left: R.langs?.[0] || "语言", op: "≠", right: R.ipCC ? `${flagEmoji(R.ipCC)} ${R.ipCC}` : "出口" };
      case "syslang":
        return { left: "系统字库/语音", op: "≠", right: R.ipCC ? `${flagEmoji(R.ipCC)} ${R.ipCC}` : "出口" };
      case "dns":
        return R.dnsCC && R.ipCC && R.dnsCC !== R.ipCC
          ? { left: `DNS ${flagEmoji(R.dnsCC)}${R.dnsCC}`, op: "≠", right: `出口 ${flagEmoji(R.ipCC)}${R.ipCC}` }
          : { single: "ECS 子网外泄" };
      case "split": {
        if (R.exits?.ex_cn?.cc === "CN" && R.ipCC && R.ipCC !== "CN") {
          return { left: `海外 ${flagEmoji(R.ipCC)}${R.ipCC}`, op: "≠", right: "直连 🇨🇳CN" };
        }
        const foreignEx = R.ipCC === "CN"
          ? Object.entries(R.exits || {}).find(([k, v]) => v?.cc && v.cc !== "CN" && !isSafariSubprobeRelay(k, v))?.[1]
          : null;
        if (foreignEx) {
          return { left: "直连 🇨🇳CN", op: "≠", right: `代理 ${flagEmoji(foreignEx.cc)}${foreignEx.cc}` };
        }
        return { single: "多出口网段分流" };
      }
      case "conn":
        if (/HTTP\/2 原始帧/.test(res?.summary || "")) return { left: claimedBrowser() || "UA", op: "≠", right: R.h2Fp?.clientGuess || "H2 帧异常" };
        if (/QUIC Initial/.test(res?.summary || "")) return { left: claimedBrowser() || "UA", op: "≠", right: R.quicFp?.stackGuess || "QUIC 栈异常" };
        if (/TLS 扩展排列/.test(res?.summary || "")) return { single: "TLS 扩展未随机洗牌" };
        if (/代理转发头/.test(res?.summary || "")) return { single: "中间层注入代理头" };
        return (tcp && tcpHuman && tcpHuman.toLowerCase() !== uaOs.toLowerCase() && !(/^(iOS|iPadOS)$/.test(uaOs) && tcpHuman === "macOS"))
          ? { left: uaOs, op: "≠", right: `${tcpHuman} SYN` }
          : tcp?.mtu && tcp.mtu < 1480
          ? { single: `MTU ${tcp.mtu} 隧道` }
          : { single: "TLS 握手异常" };
      case "synspoof":
        return { single: tcp?.synSpoofSuspect ? "TSval 时钟突变" : (isMuxTunnelSuspect(R.muxBurst) ? "Mux 粘包合并" : "DF 包头矛盾") };
      case "reality": {
        if (R.intel?.tls443?.realitySuspect) {
          return { left: R.asn || "非官方ASN", op: "≠", right: `${R.intel.tls443.realityBrand || "大厂"}证书` };
        }
        const openSvc = (R.intel?.ports?.open || []).filter(o => o.kind !== "web").map(o => `${o.port}/${o.svc}`);
        return openSvc.length ? { single: `开放 ${openSvc.slice(0, 2).join(" ")}` } : { single: ":443 开放监听" };
      }
      case "rtt": {
        const gv = analyzeRttGeo()?.violation;
        if (gv && /光速违例/.test(res?.summary || "")) {
          return { left: `${gv.name} ${gv.ms}ms`, op: "<", right: `光速下限 ${gv.floorMs}ms` };
        }
        if (R.stunRttMs != null && R.httpRtt != null && (R.httpRtt - R.stunRttMs) >= 75) {
          return { left: `TCP ${R.httpRtt}ms`, op: "≫", right: `UDP ${R.stunRttMs}ms` };
        }
        return R.srvTcpRtt != null
          ? { left: `HTTP ${R.httpRtt}ms`, op: "≫", right: `握手 ${R.srvTcpRtt}ms` }
          : { single: `RTT ${R.httpRtt ?? "--"}ms 偏高` };
      }
      case "webrtc": {
        if (R.v6mac) return { single: "IPv6 暴露 MAC" };
        const lk = getLeakedWebrtcIps();
        const lkCC = lk.length ? candidateCC(lk[0]) : "";
        if (lkCC && R.ipCC && lkCC !== R.ipCC) {
          return { left: `网页 ${flagEmoji(R.ipCC)}${R.ipCC}`, op: "≠", right: `STUN ${flagEmoji(lkCC)}${lkCC}` };
        }
        return { single: "STUN 漏真实 IP" };
      }
      case "dc":
        return { single: `${R.netKind === "dc" ? "IDC 机房段" : "共享代理"} ${R.asn || ""}`.trim() };
      case "lease":
        return { single: R.intel?.asnProfile?.inferred?.conflict ? "PeeringDB 伪家宽" : (R.intel?.consensus?.isNative === false ? "跨国广播 IP" : "商业转租段") };
      case "reputation":
        return { single: `纯净 ${R.intel?.purity?.score ?? "--"} · 脏邻 ${R.intel?.cidr?.neighbours?.dirtyCount ?? 0}` };
      case "subpixel":
        return { left: uaOs, op: "≠", right: "图形/滚动条栈" };
      case "hwvirt":
        return { single: R.gpuSoft ? "SwiftShader 软卡" : `抢占 ${R.cpuBench?.stealRatio || 1}x` };
      case "tamper":
        return { single: `${(R.lies || []).length || 1} 处接口/头矛盾` };
      case "fpb":
        if ((R.workerDiff || []).length) return { left: "主线程", op: "≠", right: "Worker 线程" };
        if ((R.swRealmDiff || []).length) return { left: "主线程", op: "≠", right: "Shared/SW 线程" };
        if (R.ufragConflict) return { left: claimedBrowser() || "UA", op: "≠", right: "SDP 媒体栈" };
        if (R.gpuTexConflict) return { left: "自报 GPU", op: "≠", right: "纹理硬件架构" };
        if (R.gpuSoft) return { single: "SwiftShader 软卡" };
        if (R.hi?.platformVersion && parseInt(R.hi.platformVersion, 10) <= 10) {
          return { left: "Apple M系", op: "≠", right: `macOS ${R.hi.platformVersion}` };
        }
        return { single: "内核/平台矛盾" };
      case "ua":
        return (R.mobileHits || []).length >= 2 ? { single: "移动端仿真矛盾" } : { left: "ClientHints", op: "≠", right: uaOs };
      case "bot":
        return res?.level === "warn"
          ? { single: R.cdpHit ? "CDP 调试附着" : R.winHeadless ? "无头窗口尺寸" : "机械轨迹" }
          : { single: (R.inputUntrusted || 0) > 0 && !(R.botHits || []).length ? "合成输入事件" : "暴露自动化特征" };
      case "fp":
        return R.etag?.seen
          ? { left: "清空存储", op: "≠", right: "ETag 命中" }
          : { single: "跨站指纹固定" };
      default:
        return { single: lv === "bad" ? "高危冲突" : "可疑" };
    }
  }

  function renderDiffHtml(diff, lv) {
    if (!diff) return "";
    if (diff.left && diff.right) {
      const opCls = lv === "bad" ? "text-rose-600 dark:text-rose-400 font-bold" : "text-amber-600 dark:text-amber-400 font-bold";
      return `<span>${esc(diff.left)}</span><span class="${opCls}">${esc(diff.op || "≠")}</span><span>${esc(diff.right)}</span>`;
    }
    return `<span>${esc(diff.single || "")}</span>`;
  }

  function renderChecksAndScore(recordHistory = false) {
    const checks = evaluateAllChecks();
    let badCnt = 0, warnCnt = 0, okCnt = 0, unverifiedCnt = 0, penalty = 0;

    const styleMap = {
      ok: {
        badgeCls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-400",
        badgeTxt: "✓",
        segCls: "bg-emerald-500",
        borderLeft: "border-l-emerald-500 dark:border-l-emerald-500/80",
        diffCls: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/12 dark:text-emerald-300",
        orderBase: 60
      },
      warn: {
        badgeCls: "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-400",
        badgeTxt: "!",
        segCls: "bg-amber-500",
        borderLeft: "border-l-amber-500 dark:border-l-amber-400",
        diffCls: "bg-amber-50 text-amber-900 dark:bg-amber-500/15 dark:text-amber-200",
        orderBase: 20
      },
      bad: {
        badgeCls: "bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-400",
        badgeTxt: "✕",
        segCls: "bg-rose-500",
        borderLeft: "border-l-rose-500 dark:border-l-rose-500",
        diffCls: "bg-rose-50 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200",
        orderBase: 0
      },
      info: {
        badgeCls: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400",
        badgeTxt: "i",
        segCls: "bg-zinc-300 dark:bg-zinc-700",
        borderLeft: "border-l-zinc-300 dark:border-l-zinc-700",
        diffCls: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400",
        orderBase: 40
      }
    };

    const RETESTABLE = new Set(["tz", "lang", "syslang", "dns", "split", "conn", "synspoof", "reality", "rtt", "webrtc", "dc", "lease", "reputation", "subpixel", "hwvirt"]);
    const TIMEOUT_SENSITIVE = new Set(["tz", "lang", "split", "reality", "rtt", "dc", "lease", "reputation"]);

    const allDefs = [...CORE_CHECKS, ...PROTO_CHECKS];
    for (let idx = 0; idx < allDefs.length; idx++) {
      const [id] = allDefs[idx];
      const row = CHECK_EL[id];
      const res = checks[id] || { level: "info", summary: "–" };
      const st = styleMap[res.level] || styleMap.info;
      const isCore = idx < CORE_CHECKS.length;
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

      const seg = $(`#segBar [data-seg="${id}"]`);
      if (seg) {
        seg.className = R.finished
          ? `flex-1 h-full rounded-full transition-colors ${active ? st.segCls : "bg-zinc-200 opacity-40 dark:bg-zinc-800"}`
          : `flex-1 h-full rounded-full transition-colors ${active ? "bg-zinc-200 dark:bg-zinc-800" : "bg-zinc-200 opacity-40 dark:bg-zinc-800"}`;
      }

      if (!row) continue;
      row.classList.toggle("opacity-50", isCore && !active);

      if (isCore) {
        // Float bad & warn anomalies directly to top of grid!
        row.style.order = String((active ? st.orderBase : 80) + idx);
        row.dataset.level = res.level;
        row.className = ckCardClass(res.level, active);
        const titleEl = $(".ck-title", row);
        if (titleEl) titleEl.className = ckTitleClass(res.level);
      }

      const isIssue = res.level === "bad" || res.level === "warn";
      const hideByFilter = isCore && ((checkFilter === "issues" && !isIssue) || (checkFilter === "ok" && res.level !== "ok"));
      row.hidden = hideByFilter;

      const badge = $(".ck-badge", row);
      if (badge) {
        badge.className = isCore
          ? `ck-badge mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full text-[10.5px] font-bold ${st.badgeCls}`
          : `ck-badge inline-flex size-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold ${st.badgeCls}`;
        badge.textContent = st.badgeTxt;
      }

      const diffEl = $(".ck-diff", row);
      if (diffEl && isCore) {
        const diff = getVisualConflict(id, res);
        diffEl.className = `ck-diff inline-flex items-center gap-1 py-0.5 px-1.5 rounded font-mono text-[10.5px] font-medium ${st.diffCls}`;
        diffEl.innerHTML = isCore && !active ? "<span>不计分</span>" : renderDiffHtml(diff, res.level);
      }

      const val = $(".ck-val", row);
      if (val) {
        val.textContent = res.summary;
        val.title = res.summary;
        val.className = isCore
          ? ckValClass(res.level, row.dataset.open === "1")
          : "ck-val maskable text-[11.5px] text-zinc-500 dark:text-zinc-400 line-clamp-2 leading-snug";
      }

      const btnHow = $(".ck-howto", row);
      const howLbl = btnHow && $(".ck-howto-label", btnHow);
      if (howLbl && isCore) howLbl.textContent = isIssue ? "改法" : "原理";

      const btnRe = $(".ck-retest", row);
      if (btnRe) btnRe.hidden = !(R.finished && RETESTABLE.has(id));

      const drawer = $(".ck-drawer", row);
      if (drawer) {
        const steps = getFixSteps(id);
        drawer.innerHTML = steps.map((s, si) => `
          <div class="flex items-start gap-2">
            <span class="mt-0.5 inline-flex size-4 shrink-0 items-center justify-center rounded-full font-mono text-[10px] font-semibold bg-zinc-200/80 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">${si + 1}</span>
            <span class="flex-1">${esc(s)}</span>
          </div>
        `).join("");
      }
    }

    const fIssues = $('#checkFilterBar [data-ckfilter="issues"]'), fOk = $('#checkFilterBar [data-ckfilter="ok"]');
    if (fIssues) fIssues.textContent = R.finished || badCnt + warnCnt ? `仅看异常 ${badCnt + warnCnt}` : "仅看异常";
    if (fOk) fOk.textContent = R.finished || okCnt ? `已通过 ${okCnt}` : "已通过";

    $("#sceneBadge").textContent = currentScene === "privacy" ? "防追踪视角" : "伪装自检";

    // Gate composite score, grade, ring gauge & priority list until all probes confirm (R.finished === true)
    if (!R.finished) {
      const sSub = $("#scoreSub");
      if (sSub) {
        sSub.textContent = `已采集 ${completedSet.size} / ${SNIFFERS.length} 项 · 全部确认后加载最终评分…`;
      }
      const tabCkPending = $("#tabChecksBadge");
      if (tabCkPending) {
        tabCkPending.textContent = "核验中";
        tabCkPending.className = "py-0.5 px-1.5 rounded-full font-mono text-[11px] bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300";
      }
      if (R.extIntel && R.extIntel.ok) renderScenarios();
      return;
    }

    // Fail-closed uncertainty penalty
    if (unverifiedCnt > 0) {
      penalty += unverifiedCnt * 5.5 + (!R.ipCC ? 14 : 0);
    }

    const score = Math.max(5, Math.min(100, Math.round(100 - penalty)));
    let grade = score >= 92 && badCnt === 0 ? "A+" : score >= 85 && badCnt === 0 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 42 ? "D" : "F";
    if (unverifiedCnt > 0) {
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

    const sNumEl = $("#scoreNum");
    if (sNumEl) {
      sNumEl.textContent = String(score);
      sNumEl.className = "text-[32px] font-bold tracking-[-0.04em] font-mono tabular-nums leading-none text-zinc-950 dark:text-white";
    }

    // Update SVG Circular Gauge Ring
    const ringArc = $("#scoreRingArc");
    if (ringArc) {
      const circ = 301.59;
      const offset = circ * (1 - Math.max(4, score) / 100);
      ringArc.style.strokeDashoffset = offset.toFixed(1);
      const strokeCls = /^A/.test(grade)
        ? "stroke-emerald-500"
        : (grade === "B" || grade === "C")
        ? "stroke-amber-500"
        : "stroke-rose-500";
      ringArc.setAttribute("class", `score-ring-arc ${strokeCls}`);
    }

    const gBadge = $("#gradeBadge");
    if (gBadge) {
      gBadge.textContent = `${grade} 级`;
      gBadge.className = "mt-1 inline-flex items-center py-0.5 px-2 rounded-full text-[11px] font-semibold " + (
        /^A/.test(grade) ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
          : grade === "B" || grade === "C" ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
          : "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
      );
    }

    $("#scoreSub").textContent = totalIssues === 0 && unverifiedCnt > 0
      ? `${unverifiedCnt} 项网络探针超时，已按不确定性降级`
      : totalIssues === 0
      ? "协议栈、出口信誉与硬件指纹全项自洽"
      : badCnt > 0
      ? `${badCnt} 项高危冲突 · 易触发验证码或风控拦截`
      : `${warnCnt} 项细节可疑 · 无致命协议冲突`;

    $("#issueCount").textContent = String(totalIssues);
    $("#issueCount").className = "text-2xl font-bold font-mono tabular-nums leading-none " + (
      badCnt > 0 ? "text-rose-600 dark:text-rose-400"
        : (warnCnt > 0 || unverifiedCnt > 0) ? "text-amber-600 dark:text-amber-400"
        : "text-emerald-600 dark:text-emerald-400"
    );
    $("#cntBad").textContent = String(badCnt);
    $("#cntWarn").textContent = String(warnCnt);
    $("#cntOk").textContent = String(okCnt);

    const tabCk = $("#tabChecksBadge");
    if (tabCk) {
      tabCk.textContent = totalIssues > 0 ? `${totalIssues} 异常` : "全过";
      tabCk.className = "py-0.5 px-1.5 rounded-full font-mono text-[11px] " + (
        badCnt > 0
          ? "bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300"
          : warnCnt > 0
          ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300"
          : "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300"
      );
    }

    // Crisp Visual Conflict Diff Rows (Zero Paragraphs!)
    const rankedIssues = CORE_CHECKS
      .map(([id, title]) => ({ id, title, lv: checks[id]?.level }))
      .filter(x => isCheckCounted(x.id) && (x.lv === "bad" || x.lv === "warn"))
      .sort((a, b) => (a.lv === "bad" ? 0 : 1) - (b.lv === "bad" ? 0 : 1) || (CHECK_WEIGHTS[b.id] || 0) - (CHECK_WEIGHTS[a.id] || 0));

    $("#topGiveaway").textContent = rankedIssues.length ? rankedIssues[0].title : "全部通过";

    const pBox = $("#priorityBox"), pList = $("#priorityList"), clearBox = $("#allClearBox");
    const moreHint = $("#priorityMoreHint");
    if (pBox && pList) {
      if (!rankedIssues.length) {
        pBox.hidden = true;
        if (clearBox) {
          clearBox.hidden = false;
          const warnMode = unverifiedCnt > 0;
          clearBox.className = "rounded-xl px-3.5 py-3 flex items-center gap-2.5 " + (
            warnMode ? "bg-amber-50/80 dark:bg-amber-500/10" : "bg-emerald-50/75 dark:bg-emerald-500/10"
          );
          const ci = $("#allClearIcon"), ct = $("#allClearTitle"), cs = $("#allClearSub");
          if (ci) {
            ci.textContent = warnMode ? "!" : "✓";
            ci.className = "inline-flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-bold text-white " + (
              warnMode ? "bg-amber-500" : "bg-emerald-600"
            );
          }
          if (ct) {
            ct.textContent = warnMode ? `${okCnt} 项通过 · ${unverifiedCnt} 项待重测` : "全部核心核验零高危冲突";
            ct.className = "text-xs font-semibold " + (warnMode ? "text-amber-950 dark:text-amber-200" : "text-emerald-950 dark:text-emerald-200");
          }
          if (cs) {
            cs.textContent = warnMode ? "可点击下方超时项右侧「重测」补齐验证" : "底层握手、出口信誉与浏览器环境一致";
            cs.className = "text-[11px] truncate " + (warnMode ? "text-amber-800/80 dark:text-amber-300/80" : "text-emerald-800/80 dark:text-emerald-300/80");
          }
        }
      } else {
        pBox.hidden = false;
        if (clearBox) clearBox.hidden = true;
        const shown = rankedIssues.slice(0, 4);
        if (moreHint) {
          moreHint.textContent = rankedIssues.length > 4 ? `其余 ${rankedIssues.length - 4} 项见下方` : "";
        }
        pList.innerHTML = shown.map(item => {
          const diff = getVisualConflict(item.id, checks[item.id]);
          const shortTitle = SHORT_CHECK_TITLE[item.id] || item.title;
          const dotCls = item.lv === "bad"
            ? "bg-rose-600 text-white"
            : "bg-amber-500 text-white";
          const pillCls = item.lv === "bad"
            ? "bg-rose-50 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200"
            : "bg-amber-50 text-amber-900 dark:bg-amber-500/15 dark:text-amber-200";
          return `
            <li>
              <button type="button" data-jumpck="${esc(item.id)}" class="w-full rounded-xl px-3 py-2 flex items-center justify-between gap-2 ring-1 ring-zinc-950/[0.06] bg-zinc-50/90 hover:bg-zinc-100/90 transition dark:bg-white/[0.03] dark:ring-white/[0.07] dark:hover:bg-white/[0.06]">
                <span class="inline-flex items-center gap-2 min-w-0">
                  <span class="inline-flex size-4 shrink-0 items-center justify-center rounded-full text-[9.5px] font-bold ${dotCls}">${item.lv === "bad" ? "✕" : "!"}</span>
                  <span class="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">${esc(shortTitle)}</span>
                </span>
                <span class="inline-flex items-center gap-1.5 shrink-0 max-w-[58%]">
                  <span class="py-0.5 px-1.5 rounded font-mono text-[10.5px] font-medium truncate inline-flex items-center gap-1 ${pillCls}">${renderDiffHtml(diff, item.lv)}</span>
                  <span class="text-[11px] font-medium text-blue-600 dark:text-blue-400">→</span>
                </span>
              </button>
            </li>
          `;
        }).join("");
      }
    }

    renderScenarios();

    // Run-over-run comparison
    if (recordHistory) {
      let prev = null;
      try { prev = JSON.parse(store.get(SK.prevChecks) || "null"); } catch (e) {}
      store.set(SK.prevChecks, JSON.stringify({ at: Date.now(), issues: totalIssues, score }));
      const cmpEl = $("#cmpBadge");
      if (cmpEl && prev && typeof prev.issues === "number") {
        const d = totalIssues - prev.issues;
        cmpEl.hidden = false;
        cmpEl.textContent = d === 0 ? "与上次持平" : d < 0 ? `比上次少 ${Math.abs(d)} 处 ↓` : `比上次多 ${d} 处 ↑`;
        cmpEl.className = "text-[11px] font-medium px-2 py-0.5 rounded-md whitespace-nowrap " + (
          d < 0 ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
            : d > 0 ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
            : "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300"
        );
      }

      let hist = [];
      try { hist = JSON.parse(store.get(SK.history) || "[]"); } catch (e) {}
      hist = [...(Array.isArray(hist) ? hist : []), { t: Date.now(), s: score }].slice(-10);
      store.set(SK.history, JSON.stringify(hist));
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

    const aiBlockedCC = ["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY", "VE"].includes(cc);
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
        [PLATFORM_BLOCKED.TikTok.includes(cc), 55, `${cc} 不在 TikTok 服务地区，注册即被地区拦截`],
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
    const isExt = !!(R.extIntel && R.extIntel.ok);
    if (!R.finished && !isExt) return;
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

      const iconEl = $(".sc-icon", card);
      if (iconEl) {
        iconEl.className = "sc-icon shrink-0 " + (
          ok ? "text-emerald-600 dark:text-emerald-400"
            : warn ? "text-amber-600 dark:text-amber-400"
            : "text-rose-600 dark:text-rose-400"
        );
      }
      const badge = $(".sc-badge", card);
      if (badge) {
        badge.textContent = ok ? "畅通" : warn ? "受限" : "高危";
        badge.className = "sc-badge inline-flex items-center py-0.5 px-1.5 rounded text-[10px] font-semibold shrink-0 " + (
          ok ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
            : warn ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
            : "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
        );
      }
      const sEl = $(".sc-score", card);
      if (sEl) {
        sEl.textContent = `${item.score}%`;
        sEl.className = "sc-score font-mono text-xl font-bold tracking-tight tabular-nums leading-none " + (
          ok ? "text-emerald-700 dark:text-emerald-400" : warn ? "text-amber-700 dark:text-amber-400" : "text-rose-600 dark:text-rose-400"
        );
      }
      const bar = $(".sc-bar", card);
      if (bar) {
        bar.style.width = `${item.score}%`;
        bar.className = "sc-bar h-full rounded-full transition-all duration-300 " + (
          ok ? "bg-emerald-500" : warn ? "bg-amber-500" : "bg-rose-500"
        );
      }
      const rEl = $(".sc-reason", card);
      if (rEl) {
        rEl.textContent = item.reason;
        rEl.title = item.reason;
      }
    }

    const sumBadge = $("#scenarioSummaryBadge");
    if (sumBadge) {
      sumBadge.textContent = `${passCnt} / ${SCENARIOS_META.length} 场景畅通`;
      sumBadge.className = "inline-flex items-center py-0.5 px-2.5 rounded-full text-xs font-semibold " + (
        passCnt >= 5 ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
          : passCnt >= 3 ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
          : "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
      );
    }
  }

  /* ---------- Forensic Identity Portrait & Visual Topology ("网站眼里的你") ---------- */
  const TILE_ICONS = {
    clock: `<svg class="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
    shield: `<svg class="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>`,
    layers: `<svg class="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/><path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65"/><path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"/></svg>`,
    chip: `<svg class="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>`,
    scan: `<svg class="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="3"/></svg>`,
    fp: `<svg class="size-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>`
  };

  function chip(text, probeIds = [], tone = "default", mask = false, punct = "") {
    const cls = tone === "bad"
      ? "bg-rose-500/10 text-rose-800 decoration-rose-400 hover:bg-rose-500/18 dark:bg-rose-500/15 dark:text-rose-300 dark:decoration-rose-400/70"
      : tone === "warn"
      ? "bg-amber-500/12 text-amber-900 decoration-amber-500/75 hover:bg-amber-500/20 dark:bg-amber-500/15 dark:text-amber-300 dark:decoration-amber-400/70"
      : tone === "ok"
      ? "bg-emerald-500/10 text-emerald-800 decoration-emerald-500/65 hover:bg-emerald-500/18 dark:bg-emerald-500/15 dark:text-emerald-300 dark:decoration-emerald-400/70"
      : "bg-zinc-900/[0.055] text-zinc-900 decoration-zinc-400 hover:bg-zinc-900/[0.1] dark:bg-white/[0.075] dark:text-zinc-100 dark:decoration-zinc-500 dark:hover:bg-white/[0.13]";
    const btn = `<button type="button" data-from="${esc(probeIds.join(","))}" class="${mask ? "maskable " : ""}probe-chip inline rounded px-1 py-px font-medium underline decoration-dotted cursor-pointer transition ${cls}">${esc(text)}</button>`;
    return punct ? `<span class="whitespace-nowrap">${btn}${esc(punct)}</span>` : btn;
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

    const cnLeak = R.exits?.ex_cn?.cc === "CN" && R.ipCC && R.ipCC !== "CN" ? R.exits.ex_cn.label : null;
    const originShort = cnLeak
      ? `🇨🇳 ${cnLeak.replace(/^中国\s*[·-]?\s*/, "")}`
      : origin?.cc
      ? `${flagEmoji(origin.cc)} ${countryName(origin.cc)}`
      : "本地终端";
    const originText = cnLeak
      ? `中国大陆 (${cnLeak})`
      : origin?.cc
      ? `${flagEmoji(origin.cc)} ${countryName(origin.cc)}用户`
      : "未知来源地区";

    const exitCity = R.srv?.geo?.city || R.ipCity || R.intel?.consensus?.city || "";
    const exitText = R.ipCC ? `${flagEmoji(R.ipCC)} ${[exitCity, countryName(R.ipCC)].filter(Boolean).join(", ")}` : (R.finished ? "出口查询超时" : "读取中…");

    // 1. Update Live 3-Node Topology Diagram
    $("#snapOrigin").textContent = originShort;
    $("#snapExit").textContent = exitText;
    $("#snapDevice").textContent = `${R.osLabel || "未知系统"} · ${shortTzCity(R.tz)}`;
    $("#snapGpu").textContent = R.gpuDiscrete ? `${R.gpuDiscrete} + ${R.gpuClean}` : (R.gpuClean || "未知显卡");

    const clientTag = $("#topoClientTag");
    if (clientTag) {
      clientTag.textContent = cnLeak ? "直连漏底" : (checks.tz?.level === "bad" ? "原时区暴露" : "终端");
      clientTag.className = "py-0.5 px-1.5 rounded text-[10px] font-semibold " + (
        cnLeak || checks.tz?.level === "bad"
          ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
          : "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400"
      );
    }

    // Topology Link 1: Client -> Egress (Split Tunnel / Relay)
    const l1Badge = $("#topoLink1Badge"), l1Line = $("#topoLine1"), l1Arrow = $("#topoArrow1"), l1Sub = $("#topoLink1Sub");
    if (l1Badge && l1Line && l1Arrow) {
      const splitLv = checks.split?.level || "info";
      if (splitLv === "bad") {
        l1Badge.textContent = "分流漏底";
        l1Badge.className = "py-0.5 px-2 rounded-full text-[10.5px] font-semibold whitespace-nowrap bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300";
        l1Line.setAttribute("stroke-dasharray", "4 4");
        l1Line.setAttribute("class", "topo-flow-anim stroke-rose-500");
        l1Arrow.setAttribute("class", "stroke-rose-500");
        if (l1Sub) l1Sub.textContent = "国内直连暴露";
      } else if (splitLv === "warn") {
        l1Badge.textContent = "多路分流";
        l1Badge.className = "py-0.5 px-2 rounded-full text-[10.5px] font-semibold whitespace-nowrap bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300";
        l1Line.setAttribute("stroke-dasharray", "4 4");
        l1Line.setAttribute("class", "topo-flow-anim stroke-amber-500");
        l1Arrow.setAttribute("class", "stroke-amber-500");
        if (l1Sub) l1Sub.textContent = "多出口网段";
      } else if (R.exitsDone) {
        l1Badge.textContent = "全局一致";
        l1Badge.className = "py-0.5 px-2 rounded-full text-[10.5px] font-semibold whitespace-nowrap bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300";
        l1Line.removeAttribute("stroke-dasharray");
        l1Line.setAttribute("class", "stroke-emerald-500");
        l1Arrow.setAttribute("class", "stroke-emerald-500");
        if (l1Sub) l1Sub.textContent = "8 路同出口";
      }
    }

    // Topology Link 2: Egress -> Probe Edge (TCP SYN / Reality / RTT)
    const l2Badge = $("#topoLink2Badge"), l2Line = $("#topoLine2"), l2Arrow = $("#topoArrow2");
    const tcp = R.srv?.packet?.tcp;
    const appleTcpName = /^(iOS|iPadOS)$/.test(R.dev?.os || "") ? R.dev.os : "macOS";
    const tcpShort = tcp ? (({ windows: "Win", apple: appleTcpName, linux: "Linux" })[tcp.osFamily || tcp.osGuess] || tcp.osGuess || "TCP") : null;
    if (l2Badge && l2Line && l2Arrow) {
      if (checks.reality?.level === "bad") {
        l2Badge.textContent = ":443 偷证书";
        l2Badge.className = "py-0.5 px-2 rounded-full text-[10.5px] font-semibold whitespace-nowrap bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300";
        l2Line.setAttribute("stroke-dasharray", "4 4");
        l2Line.setAttribute("class", "topo-flow-anim stroke-rose-500");
        l2Arrow.setAttribute("class", "stroke-rose-500");
      } else if (checks.conn?.level === "bad") {
        l2Badge.textContent = tcpShort ? `${tcpShort} SYN 代发` : "协议栈穿帮";
        l2Badge.className = "py-0.5 px-2 rounded-full text-[10.5px] font-semibold whitespace-nowrap bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300";
        l2Line.setAttribute("stroke-dasharray", "4 4");
        l2Line.setAttribute("class", "topo-flow-anim stroke-rose-500");
        l2Arrow.setAttribute("class", "stroke-rose-500");
      } else if (checks.rtt?.level === "bad" || checks.synspoof?.level === "bad") {
        l2Badge.textContent = checks.synspoof?.level === "bad" ? "SYN 改包露馅" : "多跳中转延迟";
        l2Badge.className = "py-0.5 px-2 rounded-full text-[10.5px] font-semibold whitespace-nowrap bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300";
        l2Line.setAttribute("stroke-dasharray", "4 4");
        l2Line.setAttribute("class", "topo-flow-anim stroke-rose-500");
        l2Arrow.setAttribute("class", "stroke-rose-500");
      } else if (checks.conn?.level === "warn" || checks.rtt?.level === "warn") {
        l2Badge.textContent = checks.conn?.level === "warn" ? `MTU ${tcp?.mtu || ""} 隧道` : "延迟偏高";
        l2Badge.className = "py-0.5 px-2 rounded-full text-[10.5px] font-semibold whitespace-nowrap bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300";
        l2Line.setAttribute("stroke-dasharray", "4 4");
        l2Line.setAttribute("class", "topo-flow-anim stroke-amber-500");
        l2Arrow.setAttribute("class", "stroke-amber-500");
      } else if (R.srv) {
        l2Badge.textContent = tcpShort ? `${tcpShort} 栈吻合` : "TLS 1.3 正常";
        l2Badge.className = "py-0.5 px-2 rounded-full text-[10.5px] font-semibold whitespace-nowrap bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300";
        l2Line.removeAttribute("stroke-dasharray");
        l2Line.setAttribute("class", "stroke-emerald-500");
        l2Arrow.setAttribute("class", "stroke-emerald-500");
      }
    }

    // 2. Concise 1-Line Verdict Pill (#wowAlert) — wait for R.finished before showing final verdict
    const wowEl = $("#wowAlert"), wowIcon = $("#wowIcon"), wowTitle = $("#wowTitle");
    if (wowEl && wowTitle && wowIcon) {
      if (!R.finished) {
        wowEl.className = "inline-flex items-center gap-2 rounded-full border border-zinc-200/80 bg-zinc-50 px-3 py-1 text-xs dark:bg-white/[0.04] dark:border-white/[0.08] max-w-full";
        wowIcon.className = "inline-flex size-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold bg-zinc-300 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100 animate-pulse";
        wowIcon.textContent = "…";
        wowTitle.textContent = "正在交叉核验底层协议栈、分流与出口信誉…";
        wowTitle.className = "font-semibold truncate text-zinc-900 dark:text-zinc-100";
      } else {
        let alertTone = "ok", head = "底层协议栈、出口信誉与浏览器环境全项自洽";
        if (checks.reality?.level === "bad") { alertTone = "bad"; head = "反向 :443 穿透抓获 Reality 偷证书伪装"; }
        else if (checks.conn?.level === "bad") { alertTone = "bad"; head = `TCP 协议栈穿帮：自报 ${R.dev?.os || "端侧"}，实测 ${tcpShort || "Linux"} 代发连接`; }
        else if (checks.synspoof?.level === "bad") { alertTone = "bad"; head = "跨包 TSval 时钟拆穿无状态 SYN 改包"; }
        else if (checks.split?.level === "bad") { alertTone = "bad"; head = "规则分流漏底：海外走代理，国内直连暴露宽带"; }
        else if (checks.webrtc?.level === "bad") {
          const lk = getLeakedWebrtcIps();
          const lkCC = lk.length ? candidateCC(lk[0]) : "";
          alertTone = "bad";
          head = (R.ipCC === "CN" && lkCC && lkCC !== "CN")
            ? "分流规则不一致：当前网页走直连，但 UDP/部分域名走了代理"
            : "WebRTC / IPv6 穿透暴露真实底层网络";
        }
        else if (checks.lease?.level === "bad") { alertTone = "bad"; head = "PeeringDB 流量画像拆穿伪家宽机房"; }
        else if (checks.reputation?.level === "bad") { alertTone = "bad"; head = "出口命中实时黑名单或同 C 段高危污染"; }
        else if (checks.fpb?.level === "bad") { alertTone = "bad"; head = "硬件与内核版本矛盾，暴露指纹浏览器伪装"; }
        else if (R.cacheResurrected) { alertTone = "bad"; head = "本地存储虽清空，HTTP ETag 缓存仍认出回访"; }
        else if (checks.tz?.level === "bad") { alertTone = "bad"; head = "出口位于海外，但系统时钟仍停留在原时区"; }
        else if (checks.rtt?.level === "bad") { alertTone = "bad"; head = "物理测距超光缆上限，暴露多跳代理中转"; }
        else if (checks.dc?.level === "bad") { alertTone = "bad"; head = "当前出口属于云服务器/IDC 数据中心机房段"; }
        else if (checks.tamper?.level === "bad" || checks.tamper?.level === "warn") { alertTone = checks.tamper.level; head = "检测到浏览器原型钩子或请求头不一致"; }
        else if ((R.unverifiedCnt || 0) > 0) { alertTone = "warn"; head = `${R.unverifiedCnt} 项网络情报探针超时，可单项重测`; }

        wowEl.className = "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs max-w-full " + (
          alertTone === "bad" ? "border-rose-200 bg-rose-50/90 dark:bg-rose-500/12 dark:border-rose-500/25"
            : alertTone === "warn" ? "border-amber-200 bg-amber-50/90 dark:bg-amber-500/12 dark:border-amber-500/25"
            : "border-emerald-200 bg-emerald-50/80 dark:bg-emerald-500/10 dark:border-emerald-500/20"
        );
        wowIcon.className = "inline-flex size-4 shrink-0 items-center justify-center rounded-full font-bold text-[10px] " + (
          alertTone === "bad" ? "bg-rose-600 text-white" : alertTone === "warn" ? "bg-amber-500 text-white" : "bg-emerald-600 text-white"
        );
        wowIcon.textContent = alertTone === "ok" ? "✓" : "!";
        wowTitle.textContent = head;
        wowTitle.className = "font-semibold truncate " + (
          alertTone === "bad" ? "text-rose-900 dark:text-rose-200"
            : alertTone === "warn" ? "text-amber-950 dark:text-amber-200"
            : "text-emerald-900 dark:text-emerald-200"
        );
      }
    }

    // 3. Render 6-Tile Scannable Hardware, Protocol & Reputation Matrix (#identityTiles)
    const tilesBox = $("#identityTiles");
    const pur = R.intel?.purity;
    const blCnt = R.intel?.dnsbl?.listedCount ?? 0;
    const dirty = R.intel?.cidr?.neighbours?.dirtyCount ?? 0;
    const isNative = R.intel?.consensus?.isNative;
    const cleanGpuShort = (R.gpuDiscrete || R.gpuClean || "未知显卡")
      .replace(/^ANGLE\s*\([^,]+,\s*/i, "")
      .replace(/ANGLE Metal Renderer:\s*/i, "")
      .replace(/,\s*Unspecified Version\)?$/i, "")
      .replace(/\)$/g, "")
      .trim();

    if (tilesBox) {
      const tzReady = !!R.ipCC || R.finished;
      const repReady = !!R.intel || R.finished;
      const protoReady = !!R.srv || R.finished;
      const hwReady = !!R.cpuBench || !!R.gpuSoft || R.finished;
      const fpReady = !!R.hwId || R.finished;

      const tzTone = !tzReady ? "pending" : (checks.tz?.level === "bad" || checks.lang?.level === "bad" ? "bad" : (checks.tz?.level === "warn" || checks.lang?.level === "warn" ? "warn" : "ok"));
      const repTone = !repReady ? "pending" : (checks.reputation?.level === "bad" || checks.dc?.level === "bad" ? "bad" : (checks.reputation?.level === "warn" || checks.lease?.level === "warn" ? "warn" : "ok"));
      const protoTone = !protoReady ? "pending" : (checks.conn?.level === "bad" || checks.synspoof?.level === "bad" ? "bad" : (checks.conn?.level === "warn" || checks.synspoof?.level === "warn" ? "warn" : "ok"));
      const hwTone = !hwReady ? "pending" : (R.gpuSoft || checks.hwvirt?.level === "bad" ? "bad" : (checks.hwvirt?.level === "warn" || checks.subpixel?.level === "warn" ? "warn" : "ok"));
      const brwTone = checks.tamper?.level === "bad" || checks.fpb?.level === "bad" || checks.bot?.level === "bad" ? "bad" : (checks.tamper?.level === "warn" ? "warn" : "ok");
      const fpProtected = ["brave", "rfp", "fpp", "atfp"].includes(R.shieldKind);
      const fpTone = !fpReady ? "pending" : (R.cacheResurrected ? "bad" : (fpProtected ? "ok" : "warn"));

      const tiles = [
        {
          iconKey: "clock",
          icon: TILE_ICONS.clock,
          label: "时区与语言",
          status: tzTone === "pending" ? "核验中" : tzTone === "bad" ? "穿帮" : tzTone === "warn" ? "偏差" : "对齐",
          tone: tzTone,
          val: `${shortTzCity(R.tz)} · ${R.langs?.[0] || "–"}`,
          sub: `DNS ${R.dnsCC ? flagEmoji(R.dnsCC) + " " + R.dnsCC : "探测中"} · ${R.h12 ? "12h" : "24h"} 制`,
          probes: "tz,langs,dns,ecs"
        },
        {
          iconKey: "shield",
          icon: TILE_ICONS.shield,
          label: "BGP 与黑名单",
          status: repTone === "pending" ? "查询中" : repTone === "bad" ? (R.netKind === "dc" ? "机房段" : "污染") : repTone === "warn" ? "瑕疵" : "洁净",
          tone: repTone,
          val: !repReady ? "拉取 8 源情报…" : (pur?.score != null ? `纯净度 ${pur.score} / 100` : (R.netKind === "dc" ? "IDC 机房线路" : "宽带 ISP")),
          sub: !repReady ? "核对 DNSBL 与同段脏邻居…" : `${blCnt} 黑名单 · ${dirty} 脏邻居 · ${isNative === false ? "广播IP" : "原生段"}`,
          probes: "rep_score,rep_votes,rep_dnsbl,rep_neigh"
        },
        {
          iconKey: "layers",
          icon: TILE_ICONS.layers,
          label: "传输层协议栈",
          status: protoTone === "pending" ? "抓包中" : protoTone === "bad" ? "代发穿帮" : protoTone === "warn" ? "隧道特征" : "吻合",
          tone: protoTone,
          val: !protoReady ? "嗅探 TCP SYN…" : `${tcpShort ? tcpShort + " SYN" : (R.hasH3 ? "QUIC H3" : "HTTP/2")} · TTL ${tcp?.initialTtl ?? "–"}`,
          sub: !protoReady ? "测量 TTL · MTU · TLS 栈…" : `MTU ${tcp?.mtu ?? "–"} · ${R.srvPq ? "抗量子 PQ" : "TLS 1.3"}`,
          probes: "tcp_os,ja4t,ja4,ipquirk"
        },
        {
          iconKey: "chip",
          icon: TILE_ICONS.chip,
          label: "芯片与物理屏",
          status: hwTone === "pending" ? "采样中" : hwTone === "bad" ? "虚拟化" : hwTone === "warn" ? "轻微异常" : "真机硬件",
          tone: hwTone,
          val: cleanGpuShort.length > 18 ? cleanGpuShort.slice(0, 17) + "…" : cleanGpuShort,
          sub: `${navigator.hardwareConcurrency || "?"} 核 · ${R.physScreen || "–"} · ${R.hz || 60}Hz`,
          probes: "gpu,screen,hz,cpubench"
        },
        {
          iconKey: "scan",
          icon: TILE_ICONS.scan,
          label: "沙箱与防篡改",
          status: brwTone === "bad" ? "检出伪装" : brwTone === "warn" ? "可疑钩子" : "零篡改",
          tone: brwTone,
          val: `${R.browserLabel || "浏览器"} (${R.engine || "–"})`,
          sub: `${(R.lies || []).length ? R.lies.length + " 处 API 谎言" : "52 项原型纯净"} · ${R.adblock ? "有去广告" : "无去广告"}`,
          probes: "lies,worker,iframe,h_chua"
        },
        {
          iconKey: "fp",
          icon: TILE_ICONS.fp,
          label: "物理设备锁定",
          status: fpTone === "pending" ? "计算中" : R.cacheResurrected ? "缓存暴露" : fpProtected ? "已加噪" : "固定指纹",
          tone: fpTone,
          val: `硬件 #${R.hwId ? R.hwId.slice(0, 8) : "--"}`,
          sub: !fpReady ? "校验缓存 ETag 与硬件哈希…" : (fpProtected ? `${R.shieldLabel} 动态保护` : "清 Cookie 跨浏览器仍同码"),
          probes: "hwid,fpid,etag,traces"
        }
      ];
      R.lastTiles = tiles;

      tilesBox.innerHTML = tiles.map(t => {
        const iconBoxCls = t.tone === "bad"
          ? "bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300"
          : t.tone === "warn"
          ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300"
          : t.tone === "ok"
          ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300"
          : "bg-zinc-200/80 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400";
        const pillCls = t.tone === "bad"
          ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
          : t.tone === "warn"
          ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
          : t.tone === "ok"
          ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
          : "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400";
        return `
          <button type="button" data-from="${esc(t.probes)}" class="text-left rounded-xl ring-1 ring-zinc-950/[0.06] bg-zinc-50/80 hover:bg-zinc-100/80 p-3 transition flex flex-col justify-between gap-1.5 dark:bg-white/[0.025] dark:ring-white/[0.07] dark:hover:bg-white/[0.05]">
            <div class="flex flex-wrap items-center justify-between gap-x-1.5 gap-y-1 w-full">
              <span class="inline-flex items-center gap-1.5 min-w-0">
                <span class="inline-flex size-5 shrink-0 items-center justify-center rounded-md ${iconBoxCls}">${t.icon}</span>
                <span class="text-[11px] font-medium text-zinc-500 dark:text-zinc-400 whitespace-nowrap">${esc(t.label)}</span>
              </span>
              <span class="py-0.5 px-1.5 rounded text-[10px] font-semibold shrink-0 ${pillCls}">${esc(t.status)}</span>
            </div>
            <div class="w-full min-w-0">
              <div class="text-[13px] font-bold font-mono text-zinc-950 dark:text-white truncate">${esc(t.val)}</div>
              <div class="mt-0.5 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">${esc(t.sub)}</div>
            </div>
          </button>
        `;
      }).join("");
    }

    // 4. Optional Collapsible Narrative Prose (#storyProse, with non-breaking CJK punctuation)
    const langStr = R.langs?.[0] ? `${languageName(R.langs[0])} (${R.langs[0]})` : "未知语言";
    const tzStr = R.tz ? `${tzGenericLabel(R.tz)} (${R.tz})` : "未知时区";
    const clockStr = R.h12 ? "12 小时制" : "24 小时制";
    const gStr = `${R.gpuDiscrete || ""} ${R.gpuClean || ""}`;
    const isHighRig = !!R.gpuDiscrete || /RTX\s?(30|40|50)\d0|RX\s?[79]\d{3}|Apple M\d+ (Pro|Max|Ultra)|Apple M[45]/i.test(gStr);
    const rigLabel = R.gpuSoft ? "虚拟机/软件渲染容器" : isHighRig && (R.hz || 60) >= 120 ? "高刷高性能工作站" : isHighRig ? "高算力生产力设备" : "日常主流终端";

    const p1 = `推断你来自${chip(originText, ["langs", "tz", "ex_cn"], cnLeak || (origin?.cc && origin.cc !== R.ipCC) ? "warn" : "default", !!cnLeak, "，")}当前出口位于${chip(exitText, ["ip", "geo"], "default", true, "。")}阅读语言为${chip(langStr, ["langs"], "default", false, "，")}系统时钟设在${chip(tzStr, ["tz", "tzoff"], checks.tz?.level === "bad" ? "bad" : "default", false, "，")}使用${chip(clockStr, ["hour"], "default", false, "。")}`;
    const p2 = `运行${chip(`${R.osLabel || "未知系统"} (${navigator.hardwareConcurrency || "?"} 核)`, ["os", "cpu", "arch"], "default", false, "，")}浏览器为${chip(`${R.engine || "?"} 内核 ${R.browserLabel || "浏览器"}`, ["browser", "engine", "engver"], "default", false, "，")}物理屏${chip(`${R.physScreen || "–"} · ${R.hz || 60}Hz`, ["screen", "hz"], "default", false, "，")}显卡${chip(cleanGpuShort, ["gpu", "webgpu"], R.gpuSoft ? "bad" : "default", false, "（")}${chip(rigLabel, ["gpu", "cpubench"], "default", false, "）。")}`;
    const netTypeDesc = R.netKind === "dc" ? `机房线路 (${R.org || R.asn})` : R.netKind === "mobile" ? `蜂窝移动 (${R.org || R.asn})` : `原生宽带 (${R.org || R.asn})`;
    const rttDesc = R.httpRtt != null && R.srvTcpRtt != null ? `HTTP ${R.httpRtt}ms / 握手 ${R.srvTcpRtt}ms` : "延迟已采样";
    const purityPhrase = pur?.score != null ? `纯净度${chip(`${pur.score}/100 (${pur.grade})`, ["rep_score", "rep_votes"], pur.score >= 82 ? "ok" : pur.score >= 58 ? "warn" : "bad", false, "，")}` : "";
    const p3 = `链路走${chip(netTypeDesc, ["isp", "nettype", "rep_asn"], R.netKind === "dc" ? "bad" : "ok", true, "，")}${purityPhrase}DNS 位于${chip(R.dnsCC ? `${flagEmoji(R.dnsCC)} ${countryName(R.dnsCC)}` : "未检出", ["dns", "ecs"], checks.dns?.level === "bad" ? "bad" : "default", false, "，")}测距${chip(rttDesc, ["tcprtt", "muxjitter"], checks.rtt?.level === "bad" ? "bad" : checks.rtt?.level === "warn" ? "warn" : "ok", false, "。")}`;

    $("#storyProse").innerHTML = `<p>${p1}</p><p>${p2}</p><p>${p3}</p>`;

    // 5. Compact Persona Pills
    const tags = [];
    if (checks.tz?.level === "bad" || checks.split?.level === "bad" || checks.split?.level === "warn" || checks.conn?.level === "bad" || checks.reality?.level === "bad" || R.netKind === "dc") {
      tags.push(["跨境代理特征", "bad"]);
    }
    if (checks.reality?.level === "bad") tags.push(["Reality 偷证书", "bad"]);
    if (R.netKind === "dc") tags.push(["IDC 机房段", "bad"]);
    if (R.intel?.asnProfile?.inferred?.conflict) tags.push(["伪家宽冲突", "bad"]);
    if (R.intel?.consensus?.isNative === false) tags.push(["跨国广播 IP", "warn"]);
    if ((R.intel?.cidr?.neighbours?.dirtyCount || 0) > 0) tags.push([`脏邻居 ${R.intel.cidr.neighbours.dirtyCount}`, "warn"]);
    if (R.exits?.ex_cn?.cc === "CN" && R.ipCC && R.ipCC !== "CN") tags.push(["分流漏底", "bad"]);
    if (/^(macOS|iOS|iPadOS)/.test(R.dev?.os || "")) tags.push(["Apple 生态", "info"]);
    if (isHighRig) tags.push(["高算力终端", "info"]);
    if (R.multiScreen) tags.push(["多屏办公", "info"]);
    for (const [k] of R.fontRoles || []) {
      if (k === "dev") tags.push(["开发者字库", "info"]);
      if (k === "design") tags.push(["设计向字库", "info"]);
    }
    if ((R.domExts || []).some(x => x[0] === "crypto") || (R.extWar || []).some(n => /MetaMask|Phantom|OKX|Rabby|Bitget/.test(n))) {
      tags.push(["Web3 钱包", "warn"]);
    }
    if (R.adblock) tags.push(["广告拦截", "ok"]);
    if (R.finished) {
      tags.push(["brave", "rfp", "fpp", "atfp"].includes(R.shieldKind) ? ["防指纹护盾", "ok"] : ["裸奔指纹", "neutral"]);
    }

    const tagCls = {
      bad: "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300",
      warn: "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300",
      ok: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300",
      info: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
      neutral: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800/80 dark:text-zinc-400"
    };
    $("#personaTags").innerHTML = tags.map(([label, t]) =>
      `<span class="py-0.5 px-2 rounded-full text-[11px] font-medium ${tagCls[t] || tagCls.neutral}">${esc(label)}</span>`
    ).join("");
  }

  /* ---------- Target Country / Region Alignment Simulator ---------- */
  function renderTargetSimulator() {
    const T = targetCountry || R.ipCC || "US";
    const tName = `${flagEmoji(T)} ${countryName(T)}`;

    // Sync pill active state
    $$("#targetQuickPills .tg-pill").forEach(btn => {
      const on = btn.dataset.tgcc === targetCountry;
      btn.className = "tg-pill py-1 px-2.5 rounded-lg text-xs font-medium transition " + (
        on
          ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-950"
          : "bg-white ring-1 ring-zinc-950/[0.08] text-zinc-700 hover:bg-zinc-100 dark:bg-zinc-800 dark:ring-white/[0.08] dark:text-zinc-300"
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
    const pendCnt = cards.filter(([, ok]) => ok == null).length;
    const vBadge = $("#targetVerdictBadge");
    if (vBadge) {
      if (!R.finished && pendCnt > 0 && failCnt === 0) {
        vBadge.textContent = `伪装成 ${tName}：核验中 (${6 - pendCnt}/6)…`;
        vBadge.className = "inline-flex items-center py-1 px-3 rounded-full text-xs font-medium bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
      } else if (failCnt > 0) {
        vBadge.textContent = `伪装成 ${tName}：差 ${failCnt} 项未对齐`;
        vBadge.className = "inline-flex items-center py-1 px-3 rounded-full text-xs font-medium bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300";
      } else if (pendCnt > 0) {
        vBadge.textContent = `伪装成 ${tName}：${6 - pendCnt} 项达标 · ${pendCnt} 项待确认`;
        vBadge.className = "inline-flex items-center py-1 px-3 rounded-full text-xs font-medium bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300";
      } else {
        vBadge.textContent = `伪装成 ${tName}：6 项全数达标`;
        vBadge.className = "inline-flex items-center py-1 px-3 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300";
      }
    }

    const grid = $("#targetCardsGrid");
    if (grid) {
      grid.innerHTML = cards.map(([title, ok, desc]) => {
        const iconCls = ok === true
          ? "bg-emerald-600 text-white"
          : ok === false
          ? "bg-rose-600 text-white"
          : "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-200";
        return `
          <div class="bg-white p-5 transition dark:bg-[#121418]">
            <div class="flex items-center justify-between gap-2">
              <span class="text-xs font-semibold text-zinc-950 dark:text-white">${esc(title)}</span>
              <span class="inline-flex size-4 items-center justify-center rounded-full text-[10px] font-bold ${iconCls}">${ok === true ? "✓" : ok === false ? "✕" : "–"}</span>
            </div>
            <p class="mt-2 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">${esc(desc)}</p>
          </div>
        `;
      }).join("");
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
    switchWorkspaceTab("probes");
    activeGroup = "all";
    searchQuery = "";
    const inp = $("#probeSearch");
    if (inp) inp.value = "";
    $$("#groupTabs .gtab-btn").forEach((b, i) => {
      b.setAttribute("aria-selected", i === 0 ? "true" : "false");
      b.className = "gtab-btn shrink-0 py-1.5 px-3 inline-flex items-center gap-1.5 rounded-lg text-xs font-medium transition " + (
        i === 0 ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-950" : "bg-zinc-100 text-zinc-600 hover:bg-zinc-200/80 dark:bg-zinc-800/80 dark:text-zinc-300"
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
    // Workspace Tab Switcher (click + roving ←/→ keyboard per WAI-ARIA tabs pattern)
    $("#workspaceTabs")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-wstab]");
      if (!btn || btn.dataset.wstab === activeWorkspaceTab) return;
      switchWorkspaceTab(btn.dataset.wstab);
    });
    $("#workspaceTabs")?.addEventListener("keydown", e => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
      const tabs = $$("#workspaceTabs [data-wstab]");
      const cur = tabs.findIndex(t => t.dataset.wstab === activeWorkspaceTab);
      const next = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (cur + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      e.preventDefault();
      switchWorkspaceTab(tabs[next].dataset.wstab);
      tabs[next].focus();
    });

    // Sticky workspace tab bar offset = live sticky header height (header only sticks on ≥ sm)
    const hdr = $("header.top-chrome");
    const syncHdrH = () => {
      const h = hdr && window.matchMedia("(min-width: 640px)").matches ? hdr.offsetHeight : 0;
      document.documentElement.style.setProperty("--hdr-h", `${h}px`);
    };
    syncHdrH();
    window.addEventListener("resize", syncHdrH, { passive: true });
    if (hdr && typeof ResizeObserver === "function") new ResizeObserver(syncHdrH).observe(hdr);

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
      switchWorkspaceTab("probes");
      activeGroup = "rep";
      searchQuery = "";
      const inp = $("#probeSearch");
      if (inp) inp.value = "";
      $$("#groupTabs .gtab-btn").forEach(b => {
        const on = b.dataset.gtab === "rep";
        b.setAttribute("aria-selected", on ? "true" : "false");
        b.className = "gtab-btn shrink-0 py-1.5 px-3 inline-flex items-center gap-1.5 rounded-lg text-xs font-medium transition " + (
          on ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-950" : "bg-zinc-100 text-zinc-600 hover:bg-zinc-200/80 dark:bg-zinc-800/80 dark:text-zinc-300"
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
      if (lbl) lbl.textContent = on ? "已打码" : "打码";
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
        btn.className = "scene-btn py-1 px-2 sm:px-2.5 inline-flex items-center text-xs font-medium rounded-md transition " + (
          on
            ? "bg-white text-zinc-950 shadow-2xs dark:bg-zinc-800 dark:text-white"
            : "text-zinc-600 hover:text-zinc-950 dark:text-zinc-400 dark:hover:text-zinc-100"
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
        b.className = "ckf-btn py-1 px-3 text-xs font-medium rounded-md transition " + (
          on ? "bg-white text-zinc-950 shadow-2xs dark:bg-zinc-900 dark:text-white" : "text-zinc-600 hover:text-zinc-950 dark:text-zinc-400 dark:hover:text-zinc-100"
        );
      });
      renderChecksAndScore(false);
    });

    // Priority box jump to check & open drawer
    $("#priorityList")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-jumpck]");
      if (!btn) return;
      switchWorkspaceTab("checks", { keepScroll: true });
      const row = CHECK_EL[btn.dataset.jumpck];
      if (!row) return;
      row.hidden = false;
      setCheckDrawer(row, true);
      row.scrollIntoView({ behavior: mq("(prefers-reduced-motion: reduce)") ? "auto" : "smooth", block: "center" });
    });

    // Check drawers & Single-Check Retest ("重测")
    const RETEST_RUNNERS = {
      tz: [probeLocale],
      lang: [probeLocale],
      syslang: [probeFonts, probeVoices, probeKeyboard],
      dns: [probeDns],
      split: [probeServer, probeQuicAndExits],
      conn: [probeServer, probeTlsPerm, probeQuicParams],
      synspoof: [probeServer, probeLatency],
      reality: [probeIntel],
      rtt: [probeServer, probeLatency, probeWsPing, probeWebrtc],
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
        if (dr) setCheckDrawer(row, dr.hidden);
        return;
      }
      const reBtn = e.target.closest("[data-retest]");
      if (reBtn) {
        const id = reBtn.dataset.retest;
        const fns = RETEST_RUNNERS[id] || [];
        if (!fns.length) return;
        const lbl = $(".ck-retest-label", reBtn) || reBtn;
        reBtn.disabled = true;
        lbl.textContent = "重测中…";
        for (const fn of fns) { try { await fn(); } catch (err) {} }
        if (id === "webrtc" || id === "split") {
          try { await reconcileCandidateIpMeta(); } catch (err) {}
        }
        renderChecksAndScore(false);
        renderPortrait();
        renderTargetSimulator();
        reBtn.disabled = false;
        lbl.textContent = "重测";
        showToast(`已重测「${CORE_CHECKS.find(c => c[0] === id)?.[1] || id}」`);
        return;
      }
      // 点击核心卡片空白处展开 / 收起改法（抽屉内部与文本选择不触发）
      const card = e.target.closest('.ck-card[data-proto="0"]');
      if (!card || e.target.closest(".ck-drawer, a, button")) return;
      if (String(window.getSelection?.() || "").trim()) return;
      const dr = $(".ck-drawer", card);
      if (dr) setCheckDrawer(card, dr.hidden);
    };
    $("#coreChecksList")?.addEventListener("click", onCheckContainerClick);
    $("#protoChecksList")?.addEventListener("click", onCheckContainerClick);

    // Identity tiles & prose chips -> jump & highlight source probes
    $("#appMain")?.addEventListener("click", e => {
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
          on ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-950" : "bg-zinc-100 text-zinc-600 hover:bg-zinc-200/80 dark:bg-zinc-800/80 dark:text-zinc-300"
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
      if (R.isSharedView) {
        const shareUrl = location.href;
        const lines = [
          `【WhoProbe v7.7 · 公开脱敏体检快照 #${R.shareId || "-"}】`,
          `伪装健康度: ${R.score ?? "--"}/100 (等级 ${R.grade || "-"}) · 暴露破绽: ${R.totalIssues ?? 0} 处`,
          `脱敏链接: ${shareUrl}`,
          ``,
          `[异常与风险项]`
        ];
        for (const [id, title] of CORE_CHECKS) {
          const c = R.checks?.[id];
          if (c && (c.level === "bad" || c.level === "warn")) {
            lines.push(`- [${c.level === "bad" ? "高危" : "可疑"}] ${title}: ${c.summary}`);
          }
        }
        copyText(lines.join("\n"), "已复制脱敏体检摘要");
        return;
      }
      const masked = document.body.classList.contains("is-masked");
      const pur = R.intel?.purity;
      const lines = [
        `【WhoProbe v7.7 · 191项全栈指纹与出口信誉体检报告】`,
        `伪装健康度: ${R.score ?? "--"}/100 (等级 ${R.grade || "-"}) · 暴露破绽: ${R.totalIssues ?? 0} 处`,
        `出口纯净度: ${pur ? `${pur.score}/100 (${pur.grade} 级)` : "--"} · 脏邻居: ${R.intel?.cidr?.neighbours?.dirtyCount ?? 0} 个`,
        `推断设备: ${R.osLabel || "-"} · ${R.browserLabel || "-"} · 屏幕 ${R.physScreen || "-"} @ ${R.hz || 60}Hz`,
        `显卡渲染: ${R.gpuDiscrete ? R.gpuDiscrete + " + " + R.gpuClean : (R.gpuClean || "-")}`,
        `网络出口: ${masked ? "[已隐藏]" : (R.ip || "-")} (${countryName(R.ipCC)} · ${masked ? "[运营商已隐藏]" : (R.org || "-")})`,
        `三维测距: 浏览器 HTTP ${R.httpRtt ?? "-"}ms / 控制帧 Pong ${R.wsPingRtt ?? "-"}ms / 服务端 TCP 握手 ${R.srvTcpRtt ?? "-"}ms / STUN UDP ${R.stunRttMs ?? "-"}ms`,
        `跨站指纹: ${masked ? "[已隐藏]" : (R.fpId || "-")} · 物理硬件码: ${masked ? "[已隐藏]" : (R.hwId || "-")}`,
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
        version: "7.7.1",
        timestamp: new Date().toISOString(),
        score: R.score,
        grade: R.grade,
        issues: R.totalIssues,
        purity: R.intel?.purity || null,
        scenarios: R.scenarios || null,
        inspectedIp: masked ? null : (R.extIntel?.targetIp || null),
        exit: masked ? { country: R.ipCC, netKind: R.netKind } : { ip: R.ip, country: R.ipCC, asn: R.asn, org: R.org, netKind: R.netKind },
        rtt: { browserHttpMs: R.httpRtt, wsPingPongMs: R.wsPingRtt, serverTcpHandshakeMs: R.srvTcpRtt, stunUdpMs: R.stunRttMs, muxBurst: R.muxBurst || null },
        packet: R.srv?.packet || null,
        tls443: R.intel?.tls443 || null,
        ids: { fingerprintId: R.fpId, hardwareId: R.hwId },
        checks: R.checks,
        probes: masked
          ? Object.fromEntries(Object.entries(R.values || {}).map(([k, v]) => [k, SNIFFER_MAP[k]?.mask ? "[MASKED]" : v]))
          : R.values
      };
      copyText(JSON.stringify(payload, null, 2), "已复制 191 项完整 JSON 数据");
    });

    $("#btnCopyUrl")?.addEventListener("click", () => copyText(location.href, "已复制页面链接"));

    // Privacy-Safe Share Link & Card Modal
    $("#btnShare")?.addEventListener("click", () => openOrCreateShareModal());
    $("#btnShareInline")?.addEventListener("click", () => openOrCreateShareModal());
    $("#btnCopySharedLink")?.addEventListener("click", () => openOrCreateShareModal());
    $("#btnCloseShareModal")?.addEventListener("click", () => {
      const m = $("#shareModal");
      if (m) m.hidden = true;
    });
    $("#shareModal")?.addEventListener("click", e => {
      if (e.target === $("#shareModal")) $("#shareModal").hidden = true;
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && $("#shareModal") && !$("#shareModal").hidden) {
        $("#shareModal").hidden = true;
      }
    });
    $("#btnCopyShareUrl")?.addEventListener("click", () => {
      const val = $("#shareUrlInput")?.value || "";
      if (val) copyText(val, "已复制脱敏分享链接");
    });
    $("#btnCopyShareMd")?.addEventListener("click", () => {
      const val = $("#shareMdInput")?.value || "";
      if (val) copyText(val, "已复制 Markdown 签名徽章代码");
    });

    // Rerun all 191 probes (or navigate to live self-test if viewing a shared snapshot)
    $("#btnRerun")?.addEventListener("click", () => {
      if (R.isSharedView) {
        location.href = "./";
        return;
      }
      runAll();
    });
  }

  /* ---------- Speedtest-Style Privacy-Safe Share Builder & Snapshot Hydrator ---------- */
  function scrubClientShareText(raw) {
    if (raw == null) return "";
    let s = String(raw);
    // Redact exact runtime IPs, cities, carrier strings & tracking IDs first
    const exactSecrets = [
      R.ip,
      R.dnsIp,
      R.ecsIp,
      R.v6mac,
      R.fpId,
      R.hwId,
      R.etag?.id,
      R.exits?.ex_cn?.ip,
      R.exits?.ex_intl?.ip,
      R.exits?.ex_gpt?.ip,
      R.exits?.ex_claude?.ip,
      R.exits?.ex_cf?.ip,
      ...(Array.isArray(R.rtc) ? R.rtc : []),
      ...(Array.isArray(R.lan) ? R.lan : [])
    ].filter(x => x && String(x).length >= 4);

    for (const sec of exactSecrets) {
      s = s.split(String(sec)).join("[已隐藏]");
    }
    if (R.exits?.ex_cn?.label) {
      s = s.split(R.exits.ex_cn.label).join("中国大陆宽带");
    }
    const exactCities = [R.srv?.geo?.city, R.ipCity, R.intel?.consensus?.city].filter(x => x && String(x).length >= 2);
    for (const c of exactCities) {
      s = s.split(String(c)).join(countryName(R.ipCC) || "出口地区");
    }

    s = s
      .replace(/\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b/g, "[MAC已隐藏]")
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g, "[IP已隐藏]")
      .replace(/(?<![:\w])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:\/\d{1,3})?(?![:\w])/g, m => (m.includes("::") || m.split(":").length >= 5 ? "[IPv6已隐藏]" : m));
    return s.trim();
  }

  function scrubDiffObj(d) {
    if (!d) return {};
    if (d.left && d.right) {
      return { left: scrubClientShareText(d.left), op: d.op || "≠", right: scrubClientShareText(d.right) };
    }
    return d.single ? { single: scrubClientShareText(d.single) } : {};
  }

  function buildSanitizedSharePayload() {
    const checks = R.checks || evaluateAllChecks();
    let badCnt = 0, warnCnt = 0, okCnt = 0;
    for (const [id] of CORE_CHECKS) {
      if (!isCheckCounted(id)) continue;
      const lv = checks[id]?.level;
      if (lv === "bad") badCnt++;
      else if (lv === "warn") warnCnt++;
      else if (lv === "ok") okCnt++;
    }

    const sys = inferSystemLangs({ os: R.dev?.os, sysFonts: R.fonts || [], voices: R.voices || [], kbd: R.kbd });
    const origin = inferOrigin({ langs: R.langs || [], tz: R.tz, ipcc: R.ipCC, sys, ios: /^(iOS|iPadOS)$/.test(R.dev?.os || "") });
    const cnLeak = R.exits?.ex_cn?.cc === "CN" && R.ipCC && R.ipCC !== "CN";
    const originCountryOnly = cnLeak ? "🇨🇳 中国" : (origin?.cc ? `${flagEmoji(origin.cc)} ${countryName(origin.cc)}` : "本地终端");

    const netTypeShort = R.netKind === "dc" ? "机房 IDC" : R.netKind === "mobile" ? "移动蜂窝" : R.netKind === "relay" ? "隐私中继" : "宽带 ISP";
    const exitRegionClean = `${R.ipCC ? flagEmoji(R.ipCC) + " " + countryName(R.ipCC) : "未知地区"}${R.asn ? " · " + R.asn : ""}`;
    const pur = R.intel?.purity;
    const purityText = pur?.score != null ? `信誉 ${pur.score} · ${pur.grade}` : "信誉 --";
    const purityTone = pur?.score == null ? "neutral" : pur.score >= 82 ? "ok" : pur.score >= 58 ? "warn" : "bad";

    const splitLv = checks.split?.level || "info";
    const link1Tone = splitLv === "bad" ? "bad" : splitLv === "warn" ? "warn" : R.exitsDone ? "ok" : "neutral";
    const connBad = checks.reality?.level === "bad" || checks.conn?.level === "bad" || checks.rtt?.level === "bad" || checks.synspoof?.level === "bad";
    const connWarn = !connBad && (checks.conn?.level === "warn" || checks.rtt?.level === "warn");
    const link2Tone = connBad ? "bad" : connWarn ? "warn" : R.srv ? "ok" : "neutral";

    const wowTitleTxt = scrubClientShareText($("#wowTitle")?.textContent || "");
    const wowTone = $("#wowAlert")?.className.includes("rose") ? "bad" : $("#wowAlert")?.className.includes("amber") ? "warn" : "ok";

    // Read structured 6 tiles & redact hardware hash on tile 6
    const tiles = (R.lastTiles || []).slice(0, 6).map((t, idx) => ({
      icon: t.iconKey || "shield",
      label: t.label || "",
      status: t.status || "",
      tone: t.tone === "bad" || t.tone === "warn" || t.tone === "ok" ? t.tone : "neutral",
      val: idx === 5 ? "硬件 #**** (已脱敏)" : scrubClientShareText(t.val || ""),
      sub: scrubClientShareText(t.sub || "")
    }));

    const tags = $$("#personaTags > span").map(el => {
      const c = el.className || "";
      const t = c.includes("rose") ? "bad" : c.includes("amber") ? "warn" : c.includes("emerald") ? "ok" : "info";
      return [scrubClientShareText(el.textContent || ""), t];
    });

    const rankedIssues = CORE_CHECKS
      .map(([id, title]) => ({ id, title: SHORT_CHECK_TITLE[id] || title, lv: checks[id]?.level }))
      .filter(x => isCheckCounted(x.id) && (x.lv === "bad" || x.lv === "warn"))
      .sort((a, b) => (a.lv === "bad" ? 0 : 1) - (b.lv === "bad" ? 0 : 1) || (CHECK_WEIGHTS[b.id] || 0) - (CHECK_WEIGHTS[a.id] || 0))
      .slice(0, 4)
      .map(item => ({
        id: item.id,
        title: item.title,
        lv: item.lv,
        diff: scrubDiffObj(getVisualConflict(item.id, checks[item.id]))
      }));

    const scObj = R.scenarios || computeScenarios();
    const scenarios = SCENARIOS_META.map(([id, name]) => ({
      id,
      name,
      score: scObj[id]?.score ?? 50,
      reason: scrubClientShareText(scObj[id]?.reason || "")
    }));

    const allChecks = [...CORE_CHECKS, ...PROTO_CHECKS].map(([id], idx) => {
      const res = checks[id] || { level: "info", summary: "–" };
      const isCore = idx < CORE_CHECKS.length;
      return {
        id,
        level: res.level || "info",
        counted: !isCore || isCheckCounted(id),
        diff: isCore ? scrubDiffObj(getVisualConflict(id, res)) : {},
        summary: scrubClientShareText(res.summary || "")
      };
    });

    return {
      scene: currentScene,
      score: R.score ?? 50,
      grade: R.grade || "C",
      totalIssues: R.totalIssues ?? (badCnt + warnCnt),
      badCnt,
      warnCnt,
      okCnt,
      unverifiedCnt: R.unverifiedCnt || 0,
      summary: scrubClientShareText($("#scoreSub")?.textContent || ""),
      verdict: { tone: wowTone, text: wowTitleTxt },
      topo: {
        originLabel: originCountryOnly,
        clientTag: scrubClientShareText($("#topoClientTag")?.textContent || "终端"),
        clientTone: cnLeak || checks.tz?.level === "bad" ? "bad" : "neutral",
        deviceSub: scrubClientShareText($("#snapDevice")?.textContent || ""),
        link1Badge: scrubClientShareText($("#topoLink1Badge")?.textContent || "路由核验"),
        link1Sub: scrubClientShareText($("#topoLink1Sub")?.textContent || ""),
        link1Tone,
        exitType: netTypeShort,
        exitTone: R.netKind === "dc" ? "bad" : "ok",
        purityText,
        purityTone,
        exitRegion: scrubClientShareText(exitRegionClean),
        link2Badge: scrubClientShareText($("#topoLink2Badge")?.textContent || "TLS 1.3"),
        link2Rtt: scrubClientShareText($("#kpiRttVal")?.textContent || ""),
        link2Tone,
        trackState: R.cacheResurrected ? "缓存 ETag 认出回访（ID 已脱敏）" : "新访客或隔离良好（ID 已脱敏）"
      },
      tiles,
      tags,
      priority: rankedIssues,
      scenarios,
      checks: allChecks
    };
  }

  function populateAndShowShareModal(shareRes, autoCopy = false) {
    const modal = $("#shareModal");
    if (!modal || !shareRes) return;
    const fullUrl = new URL(shareRes.path || `./r/${shareRes.id}`, document.baseURI || location.href).href;
    const badgeUrl = new URL(shareRes.badgePath || `./r/${shareRes.id}.svg`, document.baseURI || location.href).href;
    const mdCode = `[![WhoProbe](${badgeUrl})](${fullUrl})`;

    const uInp = $("#shareUrlInput"), mInp = $("#shareMdInput"), img = $("#sharePreviewImg"), dl = $("#btnDownloadShareSvg");
    if (uInp) uInp.value = fullUrl;
    if (mInp) mInp.value = mdCode;
    if (img) img.src = badgeUrl;
    if (dl) {
      dl.href = badgeUrl;
      dl.download = `whoprobe-${shareRes.id}.svg`;
    }
    modal.hidden = false;
    if (autoCopy) {
      copyText(fullUrl, "已生成脱敏分享链接并复制到剪贴板");
    }
  }

  async function openOrCreateShareModal() {
    if (!R.finished) {
      showToast("请等待 191 项探针确认完成后再生成分享链接");
      return;
    }
    if (R.shareResult) {
      populateAndShowShareModal(R.shareResult, false);
      return;
    }
    const btn = $("#btnShare"), btnTxt = $("#btnShareText");
    if (btn) btn.disabled = true;
    if (btnTxt) btnTxt.textContent = "生成中…";

    try {
      const payload = buildSanitizedSharePayload();
      const resp = await fetch("./api/who/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "omit",
        signal: AbortSignal.timeout(8000)
      });
      const data = await resp.json().catch(() => null);
      if (!resp.ok || !data || !data.ok) {
        showToast("分享链接生成失败，请稍后重试");
        return;
      }
      R.shareResult = data;
      populateAndShowShareModal(data, true);
    } catch (e) {
      showToast("网络波动，生成分享链接失败");
    } finally {
      if (btn) btn.disabled = false;
      if (btnTxt) btnTxt.textContent = "生成分享链接";
    }
  }

  function renderSharedSnapshot(sharedWrap) {
    const sid = sharedWrap.id;
    const createdAt = sharedWrap.createdAt;
    const rep = sharedWrap.report || {};

    currentScene = rep.scene === "privacy" ? "privacy" : "disguise";
    R = {
      finished: true,
      isSharedView: true,
      shareId: sid,
      shareCreatedAt: createdAt,
      score: rep.score,
      grade: rep.grade,
      totalIssues: rep.totalIssues,
      unverifiedCnt: rep.unverifiedCnt || 0,
      shareResult: {
        id: sid,
        path: `./r/${sid}`,
        badgePath: `./r/${sid}.svg`
      },
      checks: {}
    };

    // Header & Banner adjustments for Shared Snapshot View
    if ($("#ipQueryForm")) $("#ipQueryForm").hidden = true;
    if ($("#sceneSwitch")) $("#sceneSwitch").hidden = true;
    if ($("#btnMask")) $("#btnMask").hidden = true;
    if ($("#btnCopyJson")) $("#btnCopyJson").hidden = true;
    const shBtn = $("#btnShare"), shTxt = $("#btnShareText"), shInl = $("#btnShareInline");
    if (shBtn) shBtn.hidden = false;
    if (shTxt) shTxt.textContent = "分享此卡片";
    if (shInl) shInl.hidden = false;
    const rrTxt = $("#btnRerunText");
    if (rrTxt) rrTxt.textContent = "测测我的环境";

    const dtStr = createdAt ? new Date(createdAt * 1000).toLocaleString("zh-CN", { hour12: false }) : "";
    const banner = $("#sharedViewBanner"), metaTxt = $("#sharedMetaText");
    if (banner) banner.hidden = false;
    if (metaTxt) metaTxt.textContent = `快照 #${sid}${dtStr ? " · 生成于 " + dtStr : ""} · 真实出口 IP、分流 IP、精确城市与追踪哈希已彻底抹除`;

    if ($("#topProgBar")) $("#topProgBar").style.width = "100%";
    if ($("#liveDot")) $("#liveDot").className = "size-1.5 shrink-0 rounded-full bg-emerald-500";
    if ($("#liveStatusText")) $("#liveStatusText").textContent = `公开脱敏快照 #${sid}`;
    if ($("#portraitElapsed")) $("#portraitElapsed").textContent = `脱敏快照 #${sid}`;

    // 1. Hydrate Score Gauge & Spectrum
    const score = rep.score ?? 50;
    const grade = rep.grade || "C";
    const badCnt = rep.badCnt ?? 0;
    const warnCnt = rep.warnCnt ?? 0;
    const okCnt = rep.okCnt ?? 0;
    const totalIssues = rep.totalIssues ?? (badCnt + warnCnt);

    const sNum = $("#scoreNum");
    if (sNum) {
      sNum.textContent = String(score);
      sNum.className = "text-[32px] font-bold tracking-[-0.04em] font-mono tabular-nums leading-none text-zinc-950 dark:text-white";
    }
    const ringArc = $("#scoreRingArc");
    if (ringArc) {
      const circ = 301.59;
      ringArc.style.strokeDashoffset = (circ * (1 - Math.max(4, score) / 100)).toFixed(1);
      const strokeCls = /^A/.test(grade) ? "stroke-emerald-500" : (grade === "B" || grade === "C") ? "stroke-amber-500" : "stroke-rose-500";
      ringArc.setAttribute("class", `score-ring-arc ${strokeCls}`);
    }
    const gBadge = $("#gradeBadge");
    if (gBadge) {
      gBadge.textContent = `${grade} 级`;
      gBadge.className = "mt-1 inline-flex items-center py-0.5 px-2 rounded-full text-[11px] font-semibold " + (
        /^A/.test(grade) ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
          : (grade === "B" || grade === "C") ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
          : "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
      );
    }
    if ($("#scoreSub")) $("#scoreSub").textContent = rep.summary || "全栈风控与指纹体检脱敏快照";
    if ($("#sceneBadge")) $("#sceneBadge").textContent = currentScene === "privacy" ? "防追踪视角" : "伪装自检";
    if ($("#issueCount")) {
      $("#issueCount").textContent = String(totalIssues);
      $("#issueCount").className = "text-2xl font-bold font-mono tabular-nums leading-none " + (
        badCnt > 0 ? "text-rose-600 dark:text-rose-400" : warnCnt > 0 ? "text-amber-600 dark:text-amber-400" : "text-emerald-600 dark:text-emerald-400"
      );
    }
    if ($("#cntBad")) $("#cntBad").textContent = String(badCnt);
    if ($("#cntWarn")) $("#cntWarn").textContent = String(warnCnt);
    if ($("#cntOk")) $("#cntOk").textContent = String(okCnt);

    // Priority Conflict List
    const prio = Array.isArray(rep.priority) ? rep.priority : [];
    const pBox = $("#priorityBox"), pList = $("#priorityList"), clearBox = $("#allClearBox");
    if (pBox && pList) {
      if (!prio.length) {
        pBox.hidden = true;
        if (clearBox) {
          clearBox.hidden = false;
          clearBox.className = "rounded-xl px-3.5 py-3 flex items-center gap-2.5 bg-emerald-50/75 dark:bg-emerald-500/10";
          if ($("#allClearIcon")) {
            $("#allClearIcon").textContent = "✓";
            $("#allClearIcon").className = "inline-flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-bold bg-emerald-600 text-white";
          }
          if ($("#allClearTitle")) {
            $("#allClearTitle").textContent = "全部核心核验零高危冲突";
            $("#allClearTitle").className = "text-xs font-semibold text-emerald-950 dark:text-emerald-200";
          }
          if ($("#allClearSub")) {
            $("#allClearSub").textContent = "底层握手、出口信誉与浏览器环境一致";
            $("#allClearSub").className = "text-[11px] text-emerald-800/80 dark:text-emerald-300/80 truncate";
          }
        }
      } else {
        pBox.hidden = false;
        if (clearBox) clearBox.hidden = true;
        if ($("#priorityMoreHint")) {
          $("#priorityMoreHint").textContent = totalIssues > prio.length ? `其余 ${totalIssues - prio.length} 项见下方` : "";
        }
        pList.innerHTML = prio.map(item => {
          const dotCls = item.lv === "bad" ? "bg-rose-600 text-white" : "bg-amber-500 text-white";
          const pillCls = item.lv === "bad" ? "bg-rose-50 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200" : "bg-amber-50 text-amber-900 dark:bg-amber-500/15 dark:text-amber-200";
          return `
            <li>
              <button type="button" data-jumpck="${esc(item.id)}" class="w-full rounded-xl px-3 py-2 flex items-center justify-between gap-2 ring-1 ring-zinc-950/[0.06] bg-zinc-50/90 hover:bg-zinc-100/90 transition dark:bg-white/[0.03] dark:ring-white/[0.07] dark:hover:bg-white/[0.06]">
                <span class="inline-flex items-center gap-2 min-w-0">
                  <span class="inline-flex size-4 shrink-0 items-center justify-center rounded-full text-[9.5px] font-bold ${dotCls}">${item.lv === "bad" ? "✕" : "!"}</span>
                  <span class="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">${esc(item.title)}</span>
                </span>
                <span class="inline-flex items-center gap-1.5 shrink-0 max-w-[58%]">
                  <span class="py-0.5 px-1.5 rounded font-mono text-[10.5px] font-medium truncate inline-flex items-center gap-1 ${pillCls}">${renderDiffHtml(item.diff, item.lv)}</span>
                  <span class="text-[11px] font-medium text-blue-600 dark:text-blue-400">→</span>
                </span>
              </button>
            </li>
          `;
        }).join("");
      }
    }

    // 2. Hydrate Topology, Verdict & 6 Tiles
    const tp = rep.topo || {};
    if ($("#snapOrigin")) $("#snapOrigin").textContent = tp.originLabel || "端侧终端";
    if ($("#snapDevice")) $("#snapDevice").textContent = tp.deviceSub || "";
    if ($("#topoClientTag")) {
      $("#topoClientTag").textContent = tp.clientTag || "终端";
      $("#topoClientTag").className = "py-0.5 px-1.5 rounded text-[10px] font-semibold whitespace-nowrap shrink-0 " + (
        tp.clientTone === "bad" ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300" : "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400"
      );
    }
    const applyTopoConnector = (bId, lId, aId, badgeTxt, tone) => {
      const b = $(bId), l = $(lId), a = $(aId);
      if (!b || !l || !a) return;
      b.textContent = badgeTxt;
      if (tone === "bad") {
        b.className = "py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300";
        l.setAttribute("class", "topo-flow-anim stroke-rose-500");
        a.setAttribute("class", "stroke-rose-500");
      } else if (tone === "warn") {
        b.className = "py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300";
        l.setAttribute("class", "topo-flow-anim stroke-amber-500");
        a.setAttribute("class", "stroke-amber-500");
      } else if (tone === "ok") {
        b.className = "py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300";
        l.removeAttribute("stroke-dasharray");
        l.setAttribute("class", "stroke-emerald-500");
        a.setAttribute("class", "stroke-emerald-500");
      }
    };
    applyTopoConnector("#topoLink1Badge", "#topoLine1", "#topoArrow1", tp.link1Badge || "路由核验", tp.link1Tone);
    if ($("#topoLink1Sub")) $("#topoLink1Sub").textContent = tp.link1Sub || "";
    applyTopoConnector("#topoLink2Badge", "#topoLine2", "#topoArrow2", tp.link2Badge || "TLS 1.3", tp.link2Tone);
    if ($("#kpiRttVal")) $("#kpiRttVal").textContent = tp.link2Rtt || "";

    if ($("#ispTypeBadge")) {
      $("#ispTypeBadge").textContent = tp.exitType || "网络出口";
      $("#ispTypeBadge").className = "inline-flex items-center py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap shrink-0 " + (
        tp.exitTone === "bad" ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300" : "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
      );
    }
    if ($("#purityPill")) {
      $("#purityPill").textContent = tp.purityText || "信誉 --";
      $("#purityPill").className = "inline-flex items-center py-0.5 px-1.5 rounded-full text-[10px] font-mono font-semibold whitespace-nowrap shrink-0 " + (
        tp.purityTone === "ok" ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
          : tp.purityTone === "warn" ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
          : tp.purityTone === "bad" ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
          : "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
      );
    }
    if ($("#kpiExitIp")) $("#kpiExitIp").textContent = "*.*.*.* (IP 已隐藏)";
    if ($("#kpiExitGeo")) $("#kpiExitGeo").textContent = tp.exitRegion || "出口地区已脱敏";
    if ($("#kpiFpId")) $("#kpiFpId").textContent = "**** · **** (已脱敏)";
    if ($("#kpiVisitState")) $("#kpiVisitState").textContent = tp.trackState || "跨站追踪哈希已隐藏";

    const vd = rep.verdict || {};
    const wowEl = $("#wowAlert"), wowIcon = $("#wowIcon"), wowTitle = $("#wowTitle");
    if (wowEl && wowIcon && wowTitle) {
      const vt = vd.tone || "ok";
      wowEl.className = "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs max-w-full " + (
        vt === "bad" ? "border-rose-200 bg-rose-50/90 dark:bg-rose-500/12 dark:border-rose-500/25"
          : vt === "warn" ? "border-amber-200 bg-amber-50/90 dark:bg-amber-500/12 dark:border-amber-500/25"
          : "border-emerald-200 bg-emerald-50/80 dark:bg-emerald-500/10 dark:border-emerald-500/20"
      );
      wowIcon.className = "inline-flex size-4 shrink-0 items-center justify-center rounded-full font-bold text-[10px] " + (
        vt === "bad" ? "bg-rose-600 text-white" : vt === "warn" ? "bg-amber-500 text-white" : "bg-emerald-600 text-white"
      );
      wowIcon.textContent = vt === "ok" ? "✓" : "!";
      wowTitle.textContent = vd.text || rep.summary || "脱敏体检快照";
      wowTitle.className = "font-semibold truncate " + (
        vt === "bad" ? "text-rose-900 dark:text-rose-200" : vt === "warn" ? "text-amber-950 dark:text-amber-200" : "text-emerald-900 dark:text-emerald-200"
      );
    }

    const tilesBox = $("#identityTiles");
    if (tilesBox && Array.isArray(rep.tiles)) {
      tilesBox.innerHTML = rep.tiles.map(t => {
        const iconBoxCls = t.tone === "bad" ? "bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300"
          : t.tone === "warn" ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300"
          : t.tone === "ok" ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300"
          : "bg-zinc-200/80 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400";
        const pillCls = t.tone === "bad" ? "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
          : t.tone === "warn" ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
          : t.tone === "ok" ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
          : "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400";
        return `
          <div class="rounded-xl ring-1 ring-zinc-950/[0.06] bg-zinc-50/80 p-3 flex flex-col justify-between gap-1.5 dark:bg-white/[0.025] dark:ring-white/[0.07]">
            <div class="flex flex-wrap items-center justify-between gap-x-1.5 gap-y-1 w-full">
              <span class="inline-flex items-center gap-1.5 min-w-0">
                <span class="inline-flex size-5 shrink-0 items-center justify-center rounded-md ${iconBoxCls}">${TILE_ICONS[t.icon] || TILE_ICONS.shield}</span>
                <span class="text-[11px] font-medium text-zinc-500 dark:text-zinc-400 whitespace-nowrap">${esc(t.label)}</span>
              </span>
              <span class="py-0.5 px-1.5 rounded text-[10px] font-semibold shrink-0 ${pillCls}">${esc(t.status)}</span>
            </div>
            <div class="w-full min-w-0">
              <div class="text-[13px] font-bold font-mono text-zinc-950 dark:text-white truncate">${esc(t.val)}</div>
              <div class="mt-0.5 text-[11px] text-zinc-500 dark:text-zinc-400 truncate">${esc(t.sub)}</div>
            </div>
          </div>
        `;
      }).join("");
    }

    const tagCls = {
      bad: "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300",
      warn: "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300",
      ok: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300",
      info: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
      neutral: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800/80 dark:text-zinc-400"
    };
    if ($("#personaTags") && Array.isArray(rep.tags)) {
      $("#personaTags").innerHTML = rep.tags.map(([lbl, t]) =>
        `<span class="py-0.5 px-2 rounded-full text-[11px] font-medium ${tagCls[t] || tagCls.neutral}">${esc(lbl)}</span>`
      ).join("");
    }
    if ($("#storyProse")) {
      $("#storyProse").innerHTML = `<p class="text-xs text-zinc-500 dark:text-zinc-400">当前为公开脱敏分享报告，为保护分享者隐私，含真实 IP、城市与固定指纹哈希的自然语言细节已自动隐藏。</p>`;
    }

    // 3. Hydrate 6 Business Scenario Bars
    let passScen = 0;
    for (const sc of (rep.scenarios || [])) {
      const card = $(`#scenarioGrid [data-scen="${sc.id}"]`);
      if (!card) continue;
      const ok = sc.score >= 80, warn = sc.score >= 55 && sc.score < 80;
      if (ok) passScen++;
      if ($(".sc-icon", card)) $(".sc-icon", card).className = "sc-icon shrink-0 " + (ok ? "text-emerald-600 dark:text-emerald-400" : warn ? "text-amber-600 dark:text-amber-400" : "text-rose-600 dark:text-rose-400");
      if ($(".sc-badge", card)) {
        $(".sc-badge", card).textContent = ok ? "畅通" : warn ? "受限" : "高危";
        $(".sc-badge", card).className = "sc-badge inline-flex items-center py-0.5 px-1.5 rounded text-[10px] font-semibold shrink-0 " + (
          ok ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
            : warn ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
            : "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
        );
      }
      if ($(".sc-score", card)) {
        $(".sc-score", card).textContent = `${sc.score}%`;
        $(".sc-score", card).className = "sc-score font-mono text-xl font-bold tracking-tight tabular-nums leading-none " + (
          ok ? "text-emerald-700 dark:text-emerald-400" : warn ? "text-amber-700 dark:text-amber-400" : "text-rose-600 dark:text-rose-400"
        );
      }
      if ($(".sc-bar", card)) {
        $(".sc-bar", card).style.width = `${sc.score}%`;
        $(".sc-bar", card).className = "sc-bar h-full rounded-full transition-all duration-300 " + (ok ? "bg-emerald-500" : warn ? "bg-amber-500" : "bg-rose-500");
      }
      if ($(".sc-reason", card)) {
        $(".sc-reason", card).textContent = sc.reason || "";
        $(".sc-reason", card).title = sc.reason || "";
      }
    }
    if ($("#scenarioSummaryBadge")) {
      $("#scenarioSummaryBadge").textContent = `${passScen} / ${SCENARIOS_META.length} 场景畅通`;
      $("#scenarioSummaryBadge").className = "inline-flex items-center py-0.5 px-2.5 rounded-full text-xs font-semibold " + (
        passScen >= 5 ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
          : passScen >= 3 ? "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"
          : "bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
      );
    }

    // 4. Hydrate 24 Sanitized Check Cards & Spectrum Bar
    const styleMap = {
      ok: { badgeCls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-400", badgeTxt: "✓", segCls: "bg-emerald-500", borderLeft: "border-l-emerald-500 dark:border-l-emerald-500/80", diffCls: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/12 dark:text-emerald-300", orderBase: 60 },
      warn: { badgeCls: "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-400", badgeTxt: "!", segCls: "bg-amber-500", borderLeft: "border-l-amber-500 dark:border-l-amber-400", diffCls: "bg-amber-50 text-amber-900 dark:bg-amber-500/15 dark:text-amber-200", orderBase: 20 },
      bad: { badgeCls: "bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-400", badgeTxt: "✕", segCls: "bg-rose-500", borderLeft: "border-l-rose-500 dark:border-l-rose-500", diffCls: "bg-rose-50 text-rose-800 dark:bg-rose-500/15 dark:text-rose-200", orderBase: 0 },
      info: { badgeCls: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400", badgeTxt: "i", segCls: "bg-zinc-300 dark:bg-zinc-700", borderLeft: "border-l-zinc-300 dark:border-l-zinc-700", diffCls: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400", orderBase: 40 }
    };
    const ckLookup = Object.fromEntries((rep.checks || []).map(c => [c.id, c]));
    const allDefs = [...CORE_CHECKS, ...PROTO_CHECKS];
    for (let idx = 0; idx < allDefs.length; idx++) {
      const [id] = allDefs[idx];
      const item = ckLookup[id] || { level: "info", counted: true, diff: {}, summary: "–" };
      R.checks[id] = item;
      const st = styleMap[item.level] || styleMap.info;
      const isCore = idx < CORE_CHECKS.length;
      const active = item.counted !== false;

      const seg = $(`#segBar [data-seg="${id}"]`);
      if (seg) seg.className = `flex-1 h-full rounded-full transition-colors ${active ? st.segCls : "bg-zinc-200 opacity-40 dark:bg-zinc-800"}`;

      const row = CHECK_EL[id];
      if (!row) continue;
      if (isCore) {
        row.style.order = String((active ? st.orderBase : 80) + idx);
        row.dataset.level = item.level;
        row.className = ckCardClass(item.level, active);
        if ($(".ck-title", row)) $(".ck-title", row).className = ckTitleClass(item.level);
      }
      if ($(".ck-badge", row)) {
        $(".ck-badge", row).className = isCore
          ? `ck-badge mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full text-[10.5px] font-bold ${st.badgeCls}`
          : `ck-badge inline-flex size-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold ${st.badgeCls}`;
        $(".ck-badge", row).textContent = st.badgeTxt;
      }
      if ($(".ck-diff", row) && isCore) {
        $(".ck-diff", row).className = `ck-diff inline-flex items-center gap-1 py-0.5 px-1.5 rounded font-mono text-[10.5px] font-medium ${st.diffCls}`;
        $(".ck-diff", row).innerHTML = !active ? "<span>不计分</span>" : renderDiffHtml(item.diff, item.level);
      }
      if ($(".ck-val", row)) {
        $(".ck-val", row).textContent = item.summary || "–";
        $(".ck-val", row).className = isCore
          ? ckValClass(item.level, row.dataset.open === "1")
          : "ck-val text-[11.5px] text-zinc-500 dark:text-zinc-400 line-clamp-2 leading-snug";
      }
      const isIssue = item.level === "bad" || item.level === "warn";
      const howLbl = $(".ck-howto-label", row);
      if (howLbl && isCore) howLbl.textContent = isIssue ? "改法" : "原理";
      if ($(".ck-retest", row)) $(".ck-retest", row).hidden = true;
      if ($(".ck-drawer", row)) {
        const steps = getFixSteps(id);
        $(".ck-drawer", row).innerHTML = steps.map((s, si) => `
          <div class="flex items-start gap-2">
            <span class="mt-0.5 inline-flex size-4 shrink-0 items-center justify-center rounded-full font-mono text-[10px] font-semibold bg-zinc-200/80 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">${si + 1}</span>
            <span class="flex-1">${esc(s)}</span>
          </div>
        `).join("");
      }
    }

    if ($("#tabChecksBadge")) {
      $("#tabChecksBadge").textContent = totalIssues > 0 ? `${totalIssues} 异常` : "全过";
      $("#tabChecksBadge").className = "py-0.5 px-1.5 rounded-full font-mono text-[11px] " + (
        badCnt > 0 ? "bg-rose-100 text-rose-700 dark:bg-rose-500/20 dark:text-rose-300"
          : warnCnt > 0 ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300"
          : "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300"
      );
    }
    if ($("#tabRoutesBadge")) $("#tabRoutesBadge").textContent = "已脱敏";
    if ($("#probeCountBadge")) $("#probeCountBadge").textContent = "已隐藏";

    // Privacy shield notice inside raw route/probe panels in Shared View
    const privCardHtml = `
      <div class="p-8 text-center space-y-3">
        <div class="mx-auto inline-flex size-10 items-center justify-center rounded-full bg-emerald-50 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-400">
          <svg class="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
        </div>
        <h3 class="text-sm font-semibold text-zinc-950 dark:text-white">原始 IP 与底层硬件探针明细已隐私隔离</h3>
        <p class="max-w-md mx-auto text-xs leading-relaxed text-zinc-500 dark:text-zinc-400">为确保分享链接绝不泄露分享者的真实公网 IP、国内分流宽带与唯一硬件哈希，公开快照仅保留脱敏后的 24 项风控体检结论与场景评分。</p>
        <div class="pt-1">
          <a href="./" class="inline-flex items-center gap-1.5 py-2 px-4 rounded-lg text-xs font-semibold bg-zinc-900 text-white hover:bg-zinc-800 transition dark:bg-zinc-100 dark:text-zinc-950">实时检测我的当前环境 →</a>
        </div>
      </div>
    `;
    if ($("#panelRoutes")) $("#panelRoutes").innerHTML = privCardHtml;
    if ($("#explorerSection")) $("#explorerSection").innerHTML = privCardHtml;
  }

  /* ---------- Master Orchestrator ---------- */
  function resetPendingScoreUI() {
    if ($("#btnShare")) $("#btnShare").hidden = true;
    if ($("#btnShareInline")) $("#btnShareInline").hidden = true;
    const sNum = $("#scoreNum");
    if (sNum) {
      sNum.textContent = "--";
      sNum.className = "text-[32px] font-bold tracking-[-0.04em] font-mono tabular-nums leading-none text-zinc-400 dark:text-zinc-500";
    }
    const gBadge = $("#gradeBadge");
    if (gBadge) {
      gBadge.textContent = "待确认";
      gBadge.className = "mt-1 inline-flex items-center py-0.5 px-2 rounded-full text-[11px] font-semibold bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400";
    }
    const ringArc = $("#scoreRingArc");
    if (ringArc) {
      ringArc.style.strokeDashoffset = "260";
      ringArc.setAttribute("class", "score-ring-arc stroke-zinc-300 dark:stroke-zinc-700 animate-pulse");
    }
    const issCnt = $("#issueCount");
    if (issCnt) {
      issCnt.textContent = "--";
      issCnt.className = "text-2xl font-bold font-mono tabular-nums leading-none text-zinc-400 dark:text-zinc-500";
    }
    if ($("#cntBad")) $("#cntBad").textContent = "-";
    if ($("#cntWarn")) $("#cntWarn").textContent = "-";
    if ($("#cntOk")) $("#cntOk").textContent = "-";
    if ($("#cmpBadge")) $("#cmpBadge").hidden = true;
    $$("#segBar [data-seg]").forEach(seg => {
      seg.className = "flex-1 h-full rounded-full transition-colors bg-zinc-200 dark:bg-zinc-800";
    });
    const pBox = $("#priorityBox"), clearBox = $("#allClearBox");
    if (pBox) pBox.hidden = true;
    if (clearBox) {
      clearBox.hidden = false;
      clearBox.className = "rounded-xl px-3.5 py-3 flex items-center gap-2.5 bg-zinc-100/80 dark:bg-white/[0.04]";
      const ci = $("#allClearIcon"), ct = $("#allClearTitle"), cs = $("#allClearSub");
      if (ci) {
        ci.textContent = "…";
        ci.className = "inline-flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-bold bg-zinc-300 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-200 animate-pulse";
      }
      if (ct) {
        ct.textContent = "正在等待全部探针返回…";
        ct.className = "text-xs font-semibold text-zinc-800 dark:text-zinc-200";
      }
      if (cs) {
        cs.textContent = "全部确认后一次性加载最终评分与穿帮清单";
        cs.className = "text-[11px] text-zinc-500 dark:text-zinc-400 truncate";
      }
    }

    // Reset 6 Business Scenario meters to pending state
    for (const [id] of SCENARIOS_META) {
      const card = $(`#scenarioGrid [data-scen="${id}"]`);
      if (!card) continue;
      const iconEl = $(".sc-icon", card);
      if (iconEl) iconEl.className = "sc-icon shrink-0 text-zinc-500 dark:text-zinc-400";
      const badge = $(".sc-badge", card);
      if (badge) {
        badge.textContent = "待确认";
        badge.className = "sc-badge inline-flex items-center py-0.5 px-1.5 rounded text-[10px] font-semibold shrink-0 bg-zinc-200/70 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400";
      }
      const sEl = $(".sc-score", card);
      if (sEl) {
        sEl.textContent = "--%";
        sEl.className = "sc-score font-mono text-xl font-bold tracking-tight tabular-nums leading-none text-zinc-400 dark:text-zinc-500";
      }
      const bar = $(".sc-bar", card);
      if (bar) {
        bar.style.width = "12%";
        bar.className = "sc-bar h-full rounded-full bg-zinc-400 transition-all duration-300";
      }
      const rEl = $(".sc-reason", card);
      if (rEl) rEl.textContent = "等待全量探针确认后计算…";
    }
    const scSum = $("#scenarioSummaryBadge");
    if (scSum) {
      scSum.textContent = "待确认";
      scSum.className = "inline-flex items-center py-0.5 px-2.5 rounded-full text-xs font-medium bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400";
    }

    // Reset topology link badges & portrait elapsed
    const elap = $("#portraitElapsed");
    if (elap) elap.textContent = "扫描中…";
    const l1Badge = $("#topoLink1Badge"), l1Line = $("#topoLine1"), l1Arrow = $("#topoArrow1"), l1Sub = $("#topoLink1Sub");
    if (l1Badge && l1Line && l1Arrow) {
      l1Badge.textContent = "探测分流";
      l1Badge.className = "py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap bg-zinc-200/80 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
      l1Line.setAttribute("stroke-dasharray", "4 4");
      l1Line.setAttribute("class", "topo-flow-anim stroke-zinc-400 dark:stroke-zinc-600");
      l1Arrow.setAttribute("class", "stroke-zinc-400 dark:stroke-zinc-600");
      if (l1Sub) l1Sub.textContent = "路由比对";
    }
    const l2Badge = $("#topoLink2Badge"), l2Line = $("#topoLine2"), l2Arrow = $("#topoArrow2");
    if (l2Badge && l2Line && l2Arrow) {
      l2Badge.textContent = "握手抓包";
      l2Badge.className = "py-0.5 px-1.5 rounded-full text-[10px] font-semibold whitespace-nowrap bg-zinc-200/80 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
      l2Line.setAttribute("stroke-dasharray", "4 4");
      l2Line.setAttribute("class", "topo-flow-anim stroke-zinc-400 dark:stroke-zinc-600");
      l2Arrow.setAttribute("class", "stroke-zinc-400 dark:stroke-zinc-600");
    }
  }

  async function runAll() {
    const seq = ++runSeq;
    R = { t0: performance.now(), values: {}, finished: false };
    completedSet = new Set();
    resetPendingScoreUI();

    const rerunBtn = $("#btnRerun"), rerunTxt = $("#btnRerunText");
    if (rerunBtn) rerunBtn.disabled = true;
    if (rerunTxt) rerunTxt.textContent = "检测中…";
    const dot = $("#liveDot");
    if (dot) dot.className = "size-1.5 shrink-0 rounded-full bg-blue-600 animate-pulse";

    // Reset rows visually
    for (const [id] of SNIFFERS) {
      const el = ROW_EL[id];
      if (el) {
        const v = $(".probe-val", el);
        if (v) { v.textContent = "检测中…"; v.className = `probe-val ${SNIFFER_MAP[id]?.mask ? "maskable " : ""}font-mono text-xs text-right text-zinc-500 dark:text-zinc-400 truncate min-w-0 flex-1`; }
      }
    }
    updateProgress();

    // Phase 1: Synchronous & Instant Local Probes (< 30ms)
    resetInputLog();
    probeLocale();
    probeIntlDeep();
    probeTzDst();
    probeTzName();
    probeDeviceAndSpecs();
    probeStackFmt();
    probeNavAndPrefs();
    probePopupBlocker();
    probeLiesAndIframe();
    probeWinChrome();
    probeMqScreen();
    probeAutoKeys();
    probeJsEnv();
    probeNavProps();
    probeJitWarm();
    initInteractiveProbes();

    // Phase 2: Fonts, Graphics, Canvas & High-Entropy Hints (needed for composite IDs & portrait)
    await Promise.all([
      probeFonts(),
      probeGraphics(),
      probeCanvas(),
      probeSubpixelAndEngine()
    ]);
    await probeGpuFp();
    await probeHighEntropyHints();
    probeMobileConsistency();
    probeWasmFeatures();
    probeCpuArch();
    probeSysFont();
    probeStealth();
    probeAudioLatency();

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
    // WebSocket 控制帧主动 Ping 与 TLS 扩展洗牌验真在 pLat 后衔接（wss:// 新连接同时为 TLS 扩展洗牌提供第 2+ 个握手样本）
    const pWsAndTls = pLat.then(() => probeWsPing()).then(() => probeTlsPerm());
    // 多区域光速测距在微脉冲测速完成后再启动，避免并发请求干扰粘包/抖动时序
    const pGeo = pLat.then(() => probeRttGeo()).catch(() => setNA("rttgeo", "全球测距异常中止"));

    await Promise.all([
      pSrv,
      pIntel,
      pLat,
      pWsAndTls,
      pGeo,
      pExits,
      probeQuicParams(),
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
      probeSwRealm(),
      probeEtag(),
      probeTraces(),
      probeDomExtensions(),
      probeFontLocal(),
      probeCdp(),
      probeIncognito(),
      probeIpcFlood(),
      probeCspBypass(),
      probeGlWorker(),
      probeRtcSdp()
    ]);

    if (seq !== runSeq) return;

    // Phase 4: Derived Cross-Source Probes (Candidate IP Meta Reconciliation, Mux Jitter Cross-Check, IPv6 MAC, Shield Attribution, Composite Hardware/FP IDs)
    await reconcileCandidateIpMeta();
    refreshMuxJitterProbe();
    probeV6Mac();
    probeShield();
    probeHeaderForensics();
    probeClockSrc();
    refreshRttGeoProbe();
    probeInputTrust();
    probeBioDyn();
    await probeHeadless();
    probeChGrease();
    probeAiGeo();
    probeFocus();
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
    if (stTxt) stTxt.textContent = `已完成 ${completedSet.size}/${SNIFFERS.length} 项 · ${elapsedSec}s`;
    if (dot) dot.className = "size-1.5 shrink-0 rounded-full bg-emerald-500";
    const elap = $("#portraitElapsed");
    if (elap) elap.textContent = `${elapsedSec}s · ${SNIFFERS.length} 项探针`;
    if (rerunBtn) rerunBtn.disabled = false;
    if (rerunTxt) rerunTxt.textContent = "重新检测";
    if ($("#btnShare")) $("#btnShare").hidden = false;
    if ($("#btnShareInline")) $("#btnShareInline").hidden = false;
  }

  document.addEventListener("DOMContentLoaded", async () => {
    buildInitialDOM();
    bindEvents();

    const injectedShare = window.__WHOPROBE_SHARED__;
    if (injectedShare) {
      if (injectedShare.ok && injectedShare.report) {
        renderSharedSnapshot(injectedShare);
        return;
      }
      if (injectedShare.notFound) {
        try { history.replaceState(null, "", "./"); } catch (e) {}
        showToast("该分享链接不存在或已过期，正在为您执行本机检测…");
      }
    } else {
      const mShare = /\/r\/([A-Za-z0-9]{6,16})\/?$/.exec(location.pathname);
      if (mShare) {
        const fetched = await getJSON(`./api/who/share/${encodeURIComponent(mShare[1])}`, 5000, "omit").catch(() => null);
        if (fetched && fetched.ok && fetched.report) {
          renderSharedSnapshot(fetched);
          return;
        }
        try { history.replaceState(null, "", "./"); } catch (e) {}
        showToast("该分享链接不存在或已过期，正在为您执行本机检测…");
      }
    }

    runAll();
  });
})();
