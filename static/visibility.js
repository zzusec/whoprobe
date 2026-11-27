/* Website's-eye receipt. Private to the live page, not part of a share snapshot. */
(() => {
  "use strict";
  const panel = document.getElementById("panelVisibility");
  const embedded = document.getElementById("whoNavigationReceipt");
  const tab = document.getElementById("tabVisibility");
  if (!panel || !embedded) {
    if (tab) tab.hidden = true;
    return;
  }
  let nav;
  try { nav = JSON.parse(embedded.textContent); } catch (_) { return; }
  embedded.remove();
  if (!nav?.ok) return;
  document.getElementById("workspaceTabs").classList.add("visibility-tabs");

  const byId = id => document.getElementById(id);
  const node = (tag, value, cls) => {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (value != null) el.textContent = value;
    return el;
  };
  const text = value => Array.isArray(value) ? value.join(" / ") : value == null || value === "" ? "未观测" : String(value);
  const row = (list, label, value, sensitive = false) => {
    const line = node("div", null, "visibility-row");
    line.append(node("dt", label), node("dd", text(value), sensitive ? "maskable" : ""));
    list.append(line);
  };
  const present = value => value ? "收到；不回显值" : "这次未收到";
  const time = t => Number.isFinite(t) ? new Date(t).toLocaleString() : "未记录";
  const ipPort = p => !p?.ip ? null : p.port ? `${p.family === 6 ? `[${p.ip}]` : p.ip}:${p.port}` : p.ip;
  const sourceLabel = source => ({ direct: "本站直接监听", "trusted-edge": "受信边缘转交", "edge-reported": "受信入口转交地址", "origin-leg": "CDN 到本站的回源连接" })[source] || "访客侧未观测";
  const measuredProtocol = result => result?.status?.startsWith("confirmed-") ? result.connection?.httpVersion : null;

  function renderReceipt(receipt) {
    const request = receipt.request || {};
    const connection = receipt.connection || {};
    const wire = receipt.wire || {};
    const headers = byId("visibilityHeaders"), http = byId("visibilityHttp"), network = byId("visibilityNetwork");
    const packet = byId("visibilityWire");
    [headers, http, network, packet].forEach(list => list.replaceChildren());
    byId("visibilityReceiptNote").textContent = `采样于 ${time(receipt.observedAtMs)}；这份数据来自${receipt.kind === "navigation" ? "加载页面的导航请求" : "刚发送的探针请求（不携带 Cookie）"}。`;
    row(http, "方法和请求路径", `${request.method || "?"} ${request.path || "/"}`);
    row(http, "协议方案", request.scheme);
    row(http, "URL 查询参数", !request.hasQuery ? "无" : request.queryFieldCount == null ? "有；不回显" : `${request.queryFieldCount} 项；不回显`);
    row(http, "Cookie", present(request.cookiePresent));
    row(http, "认证头", present(request.authHeadersPresent));
    const headerRows = Array.isArray(request.headers) ? request.headers : [];
    for (const item of headerRows) {
      row(headers, item.name, item.value === null ? "收到；不回显值" : item.value, item.value !== null);
    }
    row(network, "收到的访客地址", receipt.peer?.ip ? `${receipt.peer.ip}（${sourceLabel(receipt.peer.source)}）` : null, true);
    row(network, "可见连接对端", ipPort(receipt.edgePeer || receipt.backendPeer), true);
    if (receipt.edgePeer) row(network, "本站后端的直接对端", ipPort(receipt.backendPeer), true);
    row(network, "入口收到的 HTTP 版本", connection.httpVersion ? `${connection.httpVersion}（${sourceLabel(connection.source)}）` : "未观测");
    row(network, "后端收到的 HTTP 版本", connection.backendProtocol);
    row(network, "边缘 TLS 版本 / 套件", [connection.tlsProtocol, connection.tlsCipher].filter(Boolean).join(" / "));
    row(network, "边缘 TLS ALPN / 曲线", [connection.tlsAlpn, connection.tlsCurves].filter(Boolean).join(" / "));
    row(network, "边缘 TLS 会话复用", connection.tlsSessionReused);

    const tcp = wire.tcp, tls = wire.tlsClientHello, h2 = wire.http2, quic = wire.quic;
    row(packet, "连接关联", wire.correlation === 'matched' || [tcp, tls, h2, quic].some(Boolean)
      ? "本请求对应连接" : "未关联到同一次连接；不按公网 IP 猜测");
    row(packet, "采集器", [wire.snifferActive ? "TCP 已启用" : "TCP 未启用", wire.tlsBridgeActive ? "H2 桥已启用" : "H2 桥未启用", wire.quicCollectorActive ? "QUIC 首包采集已启用" : "QUIC 首包采集未启用"]);
    if (tcp) {
      row(packet, "TTL / Hop Limit", tcp.observedTtl);
      row(packet, "TCP 窗口 / MSS / 缩放", [tcp.window ?? "?", tcp.mss ?? "?", tcp.wscale ?? "?"]);
      row(packet, "TCP 选项 / JA4T", [text(tcp.options), tcp.ja4t].filter(Boolean), true);
      row(packet, "ECN / TOS 或 Traffic Class", [tcp.ecn == null ? "?" : tcp.ecn ? "有" : "无", tcp.trafficClass ?? tcp.tos ?? "?"]);
      if (tcp.df != null || tcp.synIpId != null) row(packet, "IPv4 DF / IPID", [tcp.df == null ? "?" : +tcp.df, tcp.synIpId ?? "?"]);
      if (tcp.handshakeRttMs != null) row(packet, "SYN 到 ClientHello", `${tcp.handshakeRttMs} ms（不是独立测得的端到端 RTT）`);
    }
    if (tls) {
      row(packet, "TLS JA3 / JA4", [tls.ja3, tls.ja4].filter(Boolean), true);
      row(packet, "ClientHello SNI / 提议 ALPN", [tls.sni || "无可见 SNI", text(tls.alpn)], true);
      row(packet, "TLS 提议套件数 / 扩展数", [tls.cipherCount, tls.extCount]);
      row(packet, "提议密钥交换 / 证书压缩", [...(tls.keyShareGroups || []), ...(tls.certCompression || [])]);
      row(packet, "ECH 扩展", tls.echExtension ? "可见扩展；可能是 GREASE，不证明已启用 ECH" : "未见扩展");
    }
    if (h2) {
      row(packet, "HTTP/2 帧指纹", h2.akamai || h2.fingerprint, true);
      row(packet, "HTTP/2 伪头顺序", h2.pseudoOrder);
    }
    if (quic) row(packet, "QUIC Initial / JA4Q", [quic.quicVersion, quic.ja4q].filter(Boolean), true);
    byId("visibilityRestore").hidden = receipt.kind === "navigation";
  }

  function renderLocal() {
    const list = byId("visibilityLocal");
    list.replaceChildren();
    let tz;
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (_) { /* optional API */ }
    const timing = lab?.navigation?.(nav.connection);
    row(list, "语言 / 时区", [navigator.language, tz].filter(Boolean), true);
    row(list, "视口 / 像素比例", `${innerWidth}×${innerHeight} / ${devicePixelRatio}`, true);
    row(list, "屏幕 / 触点数", `${screen.width}×${screen.height} / ${navigator.maxTouchPoints ?? "未暴露"}`, true);
    row(list, "可见逻辑核数 / 内存提示", [navigator.hardwareConcurrency ?? "未暴露", navigator.deviceMemory == null ? "未暴露" : `约 ${navigator.deviceMemory} GiB`], true);
    row(list, "浏览器记录的导航协议", timing?.protocol);
    const comparison = {
      same: `协议族一致（入口 ${nav.connection?.httpVersion}）`,
      different: `协议族不同（入口 ${nav.connection?.httpVersion}）；不代表连接失败`,
      "origin-leg": "不可直接对照：入口协议只代表 CDN 回源",
      unknown: "没有可直接对照的两份协议读数"
    };
    row(list, "原导航的协议对照", comparison[timing?.comparison || "unknown"]);
    const body = timing?.body;
    row(list, "导航正文（解码前 / 后）", body
      ? `${body.encodedBytes.toLocaleString("zh-CN")} B / ${body.decodedBytes.toLocaleString("zh-CN")} B` : "未取得完整字节数");
    row(list, "还可通过脚本测量", "字体、Canvas、WebGL、WebGPU、音频、媒体能力、存储和 ICE 候选；取决于浏览器能力、权限及策略。");
  }

  const lab = window.WhoVisibilityLab;
  const settings = nav.settings || {};
  const defaultSample = new URL("./api/who/visibility/sample", document.baseURI);
  const api = async (name, body, timeout = 6500) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(new URL(`./api/who/visibility/${name}`, document.baseURI), {
        method: body == null ? "GET" : "POST", credentials: "omit", cache: "no-store",
        referrerPolicy: "no-referrer", redirect: "error", signal: controller.signal,
        ...(body == null ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      return data;
    } finally { clearTimeout(timer); }
  };
  const report = (id, message, values = []) => {
    const outlet = byId(id);
    const list = node("dl", null, "visibility-list");
    outlet.replaceChildren(node("p", message, "visibility-result-note"));
    if (values.length) {
      for (const entry of values) row(list, ...entry);
      outlet.append(list);
    }
  };
  const run = (buttonId, outputId, enabled, task) => {
    const button = byId(buttonId);
    button.disabled = !enabled;
    button.addEventListener("click", async () => {
      button.disabled = true;
      report(outputId, "正在测量…");
      try { await task(); }
      catch (err) { report(outputId, `未测出：${err?.name === "AbortError" ? "请求超时" : String(err?.message || "连接中断")}`); }
      finally { button.disabled = false; }
    });
  };

  renderReceipt(nav);
  renderLocal();
  if (document.readyState !== "complete") window.addEventListener("load", renderLocal, { once: true });
  byId("visibilityRestore").addEventListener("click", () => renderReceipt(nav));
  run("visibilityRefresh", "visibilityReceiptError", true, async () => {
    const result = await api("request");
    if (!result.ok) throw new Error("收据不可用");
    renderReceipt(result);
    byId("visibilityReceiptError").replaceChildren();
  });

  const routeNames = { ipv4: "IPv4 端点", ipv6: "IPv6 端点", h2: "HTTP/2 对照", h3: "HTTP/3 目标" };
  const routes = Object.entries(settings.routes || {}).filter(([key]) => Object.hasOwn(routeNames, key));
  if (routes.length) report("visibilityRouteResult", `待测：${routes.map(([key]) => routeNames[key]).join("、")}`);
  run("visibilityRouteGo", "visibilityRouteResult", !!lab && !!routes.length, async () => {
    const found = await Promise.all(routes.map(async ([key, url]) => {
      const first = await lab.route(url);
      // Allow the first successful response to advertise Alt-Svc; report both on a cold start.
      const second = key === "h3" && (first.status === "confirmed-h2" || first.status === "confirmed-h1") ? await lab.route(url) : null;
      const label = result => measuredProtocol(result) || (result?.reason === "origin-leg" ? "未确认浏览器协议（仅见 CDN 回源）" : result?.reason ? `未确认（${result.reason}）` : "未确认");
      const note = [label(first), ...(second ? [label(second)] : [])].join(" → ");
      return [routeNames[key], `${note}；所见出口 ${second?.peer?.ip || first?.peer?.ip || "未测出"}`, true];
    }));
    report("visibilityRouteResult", "仅代表这些测试请求。回退或超时不证明 UDP 被拦。", found);
  });

  if (settings.dns) report("visibilityDnsResult", "待测：使用仅本轮有效的自有子域。");
  run("visibilityDnsGo", "visibilityDnsResult", !!lab && !!settings.dns, async () => {
    const issued = await api("dns/start", {});
    if (!issued.ok || !/^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/.test(issued.host) || !issued.token) throw new Error("DNS 会话不可用");
    const target = new URL(defaultSample.pathname.replace(/^\/who\//, "/"), `https://${issued.host}`);
    const sample = await lab.route(target.href, { timeoutMs: 5500 });
    const result = await api("dns/result", { token: issued.token });
    const obs = Array.isArray(result.observations) ? result.observations : [];
    const values = obs.map(x => [x.qtype, `递归端 ${x.resolverIp}；${x.ecsNetwork ? `ECS ${x.ecsNetwork}` : "该查询未携带 ECS"}`, true]);
    values.push(["发向该域的 HTTPS", sample.peer?.ip ? `${sample.peer.ip} / ${measuredProtocol(sample) || "协议未确认"}` : "未完成或未能读回响应", true]);
    report("visibilityDnsResult", obs.length ? "权威端所见递归查询；不能据此判定客户端到递归端是否用 DoH/DoT。" : "本轮未观测到权威查询；不能据此判定 DNS 未泄露。", values);
  });

  const mediaLabels = { cookie: "Cookie", localStorage: "LocalStorage", indexedDB: "IndexedDB" };
  const storageLabels = { blocked: "受限", partitioned: "按顶层站点隔离", shared: "可跨站读取", inconclusive: "未确认" };
  if (settings.storage?.frameURL) report("visibilityStorageResult", "待测：将临时打开第二个站点，并使用一次性测试标记。");
  run("visibilityStorageGo", "visibilityStorageResult", !!lab && !!settings.storage?.frameURL, async () => {
    const result = await lab.storage(settings.storage);
    const rows = Object.entries(result.media || {}).map(([key, value]) => [mediaLabels[key] || key, storageLabels[value] || "未确认"]);
    report("visibilityStorageResult", result.status === "measured" ? "这次测试只代表当前浏览器对此嵌入场景的策略。" : `未确认跨站行为${result.reason ? `：${result.reason}` : ""}`, rows);
  });

  const turn = Array.isArray(settings.turnUrls) ? settings.turnUrls : [];
  byId("visibilityRtcInputs").hidden = turn.length === 0;
  if (turn.length) report("visibilityRtcResult", "待测：仅使用站方配置的 TURN。输入短期凭证，不要使用长期密码。");
  run("visibilityRtcGo", "visibilityRtcResult", !!lab && !!turn.length, async () => {
    const user = byId("visibilityRtcUser"), pass = byId("visibilityRtcPass");
    const username = user.value.trim(), credential = pass.value;
    user.value = pass.value = "";
    if (!username || !credential) throw new Error("请填写短期 TURN 凭证");
    const result = await lab.rtc({ urls: turn, username, credential });
    const pairs = Object.entries(result.selected || {}).map(([side, pair]) => {
      const candidate = c => [c?.type, c?.protocol, c?.relayProtocol, c?.ip].filter(Boolean).join(" / ") || "未暴露";
      return [`连接 ${side.toUpperCase()} 的选中候选对`, `${candidate(pair?.local)} ↔ ${candidate(pair?.remote)}${Number.isFinite(pair?.rttMs) ? `，RTT ${pair.rttMs} ms` : ""}`, true];
    });
    report("visibilityRtcResult", result.status === "connected" ? "数据通道完成往返。这是自有 TURN 中继路径，不代表直连或真实公网 IP。" : `未完成往返${result.reason ? `：${result.reason}` : ""}`, pairs);
  });

  let routePrefix = "";
  run("visibilityBgpGo", "visibilityBgpResult", false, async () => {
    if (!routePrefix) throw new Error("未获取可用前缀");
    const result = await api(`bgp?prefix=${encodeURIComponent(routePrefix)}`);
    const rows = [
      ["路由档案前缀", result.prefix, true],
      ["观测来源", result.source],
      ["观测窗口", [result.window?.start, result.window?.end].filter(Boolean)],
      ["起源 ASN", (result.origins || []).map(asn => `AS${asn}`)],
    ];
    for (const item of (result.timeline || []).slice(0, 16)) {
      rows.push([`${item.start} – ${item.end}`, (item.origins || []).map(asn => `AS${asn}`)]);
    }
    const desc = result.status === "observed"
      ? [result.originChanged ? "期间见过起源变化" : "期间未见起源变化", result.multiOrigin ? "见过同一时间多个起源" : "未见同一时间多个起源"].join("；") + "。不代表全球视角或路由劫持。"
      : result.status === "not_observed" ? "档案在该窗口未观测到这个精确前缀。" : "档案暂不可用或该前缀不适用。";
    report("visibilityBgpResult", desc, rows);
  });
  window.WhoVisibilityPanel = {
    updateIntel(intel) {
      if (!intel?.ok || intel.isSelfEgress === false) return;
      const coverage = intel.purity?.coverage;
      if (coverage) report("visibilityCoverage", intel.purity?.uncertain ? "情报覆盖不足，不把未知当作干净。" : "只对当前采样来源作判断，并非网站风控通过率。", [
        ["可用来源 / 适用来源", `${coverage.known}/${coverage.applicable}`],
        ["未知 / 不适用", [coverage.unknown, coverage.notApplicable]],
        ["数据来源状态", (intel.purity.evidence || []).map(x => `${x.name || x.id}：${({ hit: "命中", clear: "明确未命中", observed: "有观测", unknown: "未知", not_applicable: "不适用" })[x.status] || "未知"}`).join("；")],
      ]);
      const previous = routePrefix;
      routePrefix = intel.consensus?.prefix || "";
      if (previous !== routePrefix) {
        byId("visibilityBgpGo").disabled = !routePrefix;
        report("visibilityBgpResult", routePrefix ? "待测：只发送公开路由前缀，不发送单个访客 IP。" : "未获得路由前缀。");
      }
    },
  };
})();
