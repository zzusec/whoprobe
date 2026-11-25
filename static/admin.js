/* WhoProbe v7.8.0 — Self-Hosted Admin Analytics & Share Snapshot Inspector */
(function () {
  "use strict";

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
  const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

  let REG_ZH = null;
  try { REG_ZH = new Intl.DisplayNames(["zh-CN"], { type: "region" }); } catch (e) {}

  function flagEmoji(cc) {
    if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return "🌐";
    const u = cc.toUpperCase() === "TW" ? "CN" : cc.toUpperCase();
    return String.fromCodePoint(0x1F1E6 + u.charCodeAt(0) - 65, 0x1F1E6 + u.charCodeAt(1) - 65);
  }

  function countryName(cc) {
    if (!cc) return "";
    const u = String(cc).toUpperCase();
    if (u === "TW") return "中国台湾";
    if (u === "HK") return "中国香港";
    if (u === "MO") return "中国澳门";
    try { return (REG_ZH && REG_ZH.of(u)) || u; } catch (e) { return u; }
  }

  function fmtTime(ts) {
    if (!ts) return "–";
    const d = new Date(ts * 1000);
    return d.toLocaleString("zh-CN", {
      timeZone: "Asia/Shanghai",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    });
  }

  function toast(msg) {
    const el = $("#admToast");
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { el.hidden = true; }, 2200);
  }

  async function copyText(txt, label = "已复制") {
    try {
      await navigator.clipboard.writeText(txt);
      toast(label);
    } catch (e) {}
  }

  const STATE = {
    tab: "visits",
    day: "",
    event: "",
    q: "",
    offset: 0,
    limit: 60,
    overview: null,
    currentModalShareId: ""
  };

  async function apiGet(path) {
    const r = await fetch(path, { cache: "no-store", credentials: "same-origin" });
    if (r.status === 401) {
      showLogin();
      return null;
    }
    const j = await r.json().catch(() => null);
    return r.ok && j?.ok ? j : null;
  }

  function showLogin(errMsg = "") {
    $("#dashView").hidden = true;
    $("#btnRefreshAdm").hidden = true;
    $("#btnAdmLogout").hidden = true;
    $("#loginView").hidden = false;
    const errEl = $("#loginErrMsg");
    if (errEl) {
      errEl.textContent = errMsg;
      errEl.hidden = !errMsg;
    }
    setTimeout(() => $("#admPwdInput")?.focus(), 50);
  }

  function showDash() {
    $("#loginView").hidden = true;
    $("#dashView").hidden = false;
    $("#btnRefreshAdm").hidden = false;
    $("#btnAdmLogout").hidden = false;
  }

  function renderOverview(ov) {
    STATE.overview = ov;
    const k = ov.kpis || {};
    $("#kpiTodayUv").textContent = String(k.todayUv ?? 0);
    $("#kpiTodaySub").textContent = `总访问 ${k.todayPv ?? 0} 次 · 检测 ${k.todayScans ?? 0} 次`;

    const dUv = (k.todayUv ?? 0) - (k.yesterdayUv ?? 0);
    const dBadge = $("#kpiDeltaBadge");
    if (dBadge) {
      dBadge.textContent = dUv === 0 ? "较昨日持平" : dUv > 0 ? `较昨日 +${dUv}` : `较昨日 ${dUv}`;
      dBadge.className = "py-0.5 px-1.5 rounded text-[10.5px] font-mono font-semibold " + (
        dUv > 0 ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
          : dUv < 0 ? "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400"
          : "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300"
      );
    }

    $("#kpiYestUv").textContent = String(k.yesterdayUv ?? 0);
    $("#kpiYestSub").textContent = `昨日总访问 ${k.yesterdayPv ?? 0} 次`;

    $("#kpi7dUv").textContent = `${k.days7Uv ?? 0} 人`;
    $("#kpi30dSub").textContent = `30日独立 IP ${k.days30Uv ?? 0} · 访问 ${k.days30Pv ?? 0}`;

    $("#kpiShareViews").textContent = `${k.totalShareViews ?? 0} 次`;
    $("#kpiTodayShareBadge").textContent = `今日看 ${k.todayShareViews ?? 0} / 发 ${k.todayShareCreates ?? 0}`;
    $("#kpiShareSub").textContent = `当前在线有效分享报告 ${k.totalShares ?? 0} 份`;

    const regBox = $("#kpiTopRegions");
    const regs = (ov.topCountries || []).slice(0, 3);
    if (regBox) {
      regBox.innerHTML = regs.length
        ? regs.map(r => `
            <div class="flex items-center justify-between gap-2">
              <span class="truncate">${flagEmoji(r.cc)} ${esc(countryName(r.cc))}</span>
              <span class="shrink-0 font-semibold text-zinc-900 dark:text-zinc-100">${r.uv} IP <span class="text-zinc-400 font-normal">(${r.pv})</span></span>
            </div>
          `).join("")
        : `<div class="text-zinc-400">等待首批访客记录…</div>`;
    }

    // Render 30-day interactive bar chart
    const daily = ov.daily || [];
    const maxVal = Math.max(1, ...daily.map(d => Math.max(d.pv || 0, d.uv || 0)));
    const chartBox = $("#dailyChartBox");
    if (chartBox) {
      chartBox.innerHTML = daily.map(d => {
        const pvPct = d.pv > 0 ? Math.max(8, Math.round((d.pv / maxVal) * 100)) : 2;
        const uvPct = d.uv > 0 ? Math.max(6, Math.round((d.uv / maxVal) * 100)) : 0;
        const selected = STATE.day === d.day;
        const shortDay = d.day.slice(5);
        const tip = `${d.day}\n独立访客 (UV): ${d.uv} 人\n总访问 (PV): ${d.pv} 次\n主页检测: ${d.scans} · 打开分享: ${d.shareViews} · 生成分享: ${d.shareCreates}`;
        return `
          <button type="button" data-daybar="${esc(d.day)}" title="${esc(tip)}" class="group relative flex-1 min-w-0 h-full flex flex-col items-center justify-end gap-1 focus:outline-none">
            <span class="text-[9.5px] font-mono tabular-nums ${d.uv > 0 ? "text-zinc-600 dark:text-zinc-300" : "text-transparent"} group-hover:text-zinc-950 dark:group-hover:text-white">${d.uv || ""}</span>
            <div class="w-full flex-1 flex items-end justify-center">
              <div class="relative w-full max-w-[22px] rounded-t-md transition-all ${selected ? "ring-2 ring-blue-500 bg-blue-200/80 dark:bg-blue-500/30" : d.pv > 0 ? "bg-zinc-200/90 group-hover:bg-zinc-300 dark:bg-zinc-800 dark:group-hover:bg-zinc-700" : "bg-zinc-200/40 dark:bg-zinc-800/40"}" style="height: ${pvPct}%">
                ${uvPct > 0 ? `<div class="w-full rounded-t-md transition-all ${selected ? "bg-blue-600 dark:bg-blue-400" : "bg-zinc-900 dark:bg-zinc-100"}" style="height: ${Math.min(100, Math.round((d.uv / Math.max(1, d.pv)) * 100))}%"></div>` : ""}
              </div>
            </div>
            <span class="text-[9.5px] font-mono tabular-nums truncate w-full text-center ${selected ? "font-bold text-blue-600 dark:text-blue-400" : "text-zinc-400 dark:text-zinc-500"}">${esc(shortDay)}</span>
          </button>
        `;
      }).join("");
    }

    const dayBtn = $("#btnClearDayFilter");
    if (dayBtn) {
      dayBtn.hidden = !STATE.day;
      if (STATE.day) dayBtn.textContent = `仅看 ${STATE.day} ✕`;
    }

    renderUniqueIpsTable(ov.topIps || []);
  }

  const EVENT_BADGE = {
    scan: ["主页检测", "bg-blue-50 text-blue-700 dark:bg-blue-500/15 dark:text-blue-300"],
    share_view: ["打开分享页", "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"],
    share_create: ["生成分享页", "bg-purple-50 text-purple-700 dark:bg-purple-500/15 dark:text-purple-300"],
    ip_query: ["查外部 IP", "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300"]
  };

  function gradePillCls(grade) {
    const g = String(grade || "");
    if (/^A/.test(g)) return "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-300";
    if (g === "B" || g === "C") return "bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-300";
    return "bg-rose-100 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300";
  }

  async function loadVisits() {
    const qs = new URLSearchParams({
      day: STATE.day,
      event: STATE.event,
      q: STATE.q,
      limit: String(STATE.limit),
      offset: String(STATE.offset)
    });
    const res = await apiGet(`./api/who/admin/visits?${qs}`);
    if (!res) return;

    $("#badgeVisitsCnt").textContent = String(res.total || 0);
    const tbody = $("#visitsTableBody");
    if (!tbody) return;

    if (!res.items?.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="py-10 text-center text-zinc-400">暂无匹配的访问记录</td></tr>`;
    } else {
      tbody.innerHTML = res.items.map(r => {
        const [evLabel, evCls] = EVENT_BADGE[r.event] || [r.event, "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"];
        const geoTxt = [r.cc ? `${flagEmoji(r.cc)} ${countryName(r.cc)}` : "", r.city, r.asn, r.org].filter(Boolean).join(" · ") || "–";
        const devTxt = [r.os, r.browser, r.tcpOs ? `(${r.tcpOs})` : ""].filter(Boolean).join(" · ");

        let detailHtml = `<span class="text-zinc-400">–</span>`;
        if (r.shareId) {
          const ss = r.shareSummary || {};
          if (ss.exists) {
            detailHtml = `
              <button type="button" data-previewshare="${esc(r.shareId)}" class="inline-flex items-center gap-1.5 py-1 px-2 rounded-lg ring-1 ring-zinc-950/[0.08] bg-zinc-50 hover:bg-zinc-100 transition text-left max-w-[300px] dark:bg-white/[0.04] dark:ring-white/[0.1] dark:hover:bg-white/[0.08]">
                <span class="font-mono font-bold text-zinc-900 dark:text-white shrink-0">#${esc(r.shareId)}</span>
                <span class="py-0.5 px-1.5 rounded font-mono text-[10px] font-bold shrink-0 ${gradePillCls(ss.grade)}">${esc(ss.score ?? "--")}·${esc(ss.grade || "-")}</span>
                <span class="text-[11px] text-zinc-600 dark:text-zinc-300 truncate">${esc(ss.exitRegion || ss.verdict || "点击查看画面")}</span>
              </button>
            `;
          } else {
            detailHtml = `<span class="font-mono text-zinc-400">#${esc(r.shareId)} (已删除/过期)</span>`;
          }
        } else if (r.targetIp) {
          detailHtml = `<a href="./?ip=${encodeURIComponent(r.targetIp)}" target="_blank" rel="noopener" class="font-mono text-blue-600 hover:underline dark:text-blue-400">查 ${esc(r.targetIp)} ↗</a>`;
        }

        return `
          <tr class="hover:bg-zinc-50/80 dark:hover:bg-white/[0.02] transition">
            <td class="py-2.5 px-4 font-mono whitespace-nowrap text-zinc-600 dark:text-zinc-400">${esc(fmtTime(r.ts))}</td>
            <td class="py-2.5 px-3 whitespace-nowrap"><span class="py-0.5 px-2 rounded-md text-[11px] font-semibold ${evCls}">${esc(evLabel)}</span></td>
            <td class="py-2.5 px-3 whitespace-nowrap">
              <div class="inline-flex items-center gap-1.5">
                <button type="button" data-filterip="${esc(r.ip)}" class="font-mono font-semibold text-zinc-950 hover:text-blue-600 dark:text-white dark:hover:text-blue-400" title="筛选此 IP 的全部轨迹">${esc(r.ip)}</button>
                <button type="button" data-copyip="${esc(r.ip)}" class="text-[10px] text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200" title="复制 IP">复制</button>
                <a href="./?ip=${encodeURIComponent(r.ip)}" target="_blank" rel="noopener" class="text-[10px] text-blue-600 hover:underline dark:text-blue-400" title="穿透查询该 IP 信誉">信誉↗</a>
              </div>
            </td>
            <td class="py-2.5 px-3 max-w-[250px] truncate text-zinc-700 dark:text-zinc-300" title="${esc(geoTxt)}">${esc(geoTxt)}</td>
            <td class="py-2.5 px-3 max-w-[230px] truncate text-zinc-600 dark:text-zinc-400" title="${esc(r.ua || devTxt)}">${esc(devTxt)}</td>
            <td class="py-2.5 px-4">${detailHtml}</td>
          </tr>
        `;
      }).join("");
    }

    const start = res.total ? STATE.offset + 1 : 0;
    const end = Math.min(res.total, STATE.offset + (res.items?.length || 0));
    $("#visitsPageInfo").textContent = res.total ? `显示第 ${start}–${end} 条 / 共 ${res.total} 条` : "共 0 条记录";
    $("#btnPrevPage").disabled = STATE.offset <= 0;
    $("#btnNextPage").disabled = STATE.offset + STATE.limit >= res.total;
  }

  async function loadShares() {
    const qs = new URLSearchParams({ q: STATE.q, limit: "80", offset: "0" });
    const res = await apiGet(`./api/who/admin/shares?${qs}`);
    if (!res) return;
    $("#badgeSharesCnt").textContent = String(res.total || 0);

    const grid = $("#sharesGrid");
    if (!grid) return;
    if (!res.items?.length) {
      grid.innerHTML = `<div class="col-span-full surface-sheet rounded-2xl p-10 text-center text-xs text-zinc-400">当前尚无分享报告记录</div>`;
      return;
    }

    grid.innerHTML = res.items.map(s => {
      const creatorDesc = s.creatorIp
        ? `${s.creatorIp}${s.creatorCc ? " (" + flagEmoji(s.creatorCc) + " " + (s.creatorCity || countryName(s.creatorCc)) + ")" : ""}`
        : "后台上线前历史存量";
      const lastViewDesc = s.viewCount > 0
        ? `被打开 ${s.viewCount} 次 · 最近 ${fmtTime(s.lastViewedAt)}${s.lastViewerIp ? " (" + s.lastViewerIp + ")" : ""}`
        : "暂无人打开过此链接";

      return `
        <article class="surface-sheet rounded-2xl overflow-hidden flex flex-col justify-between">
          <div>
            <!-- Live Rendered SVG Result Card -->
            <button type="button" data-previewshare="${esc(s.id)}" class="block w-full bg-[#0B0E14] border-b border-zinc-950/[0.08] dark:border-white/[0.08] overflow-hidden group cursor-pointer" title="点击展开完整 24 项详情与打开者 IP 列表">
              <img src="./r/${esc(s.id)}.svg" loading="lazy" alt="分享卡片 #${esc(s.id)}" class="w-full h-auto block aspect-[2/1] group-hover:scale-[1.01] transition-transform duration-200">
            </button>

            <div class="p-4 space-y-2 text-xs">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex items-center gap-2">
                  <span class="font-mono font-bold text-zinc-950 dark:text-white">#${esc(s.id)}</span>
                  <span class="py-0.5 px-1.5 rounded font-mono text-[10.5px] font-bold ${gradePillCls(s.grade)}">${esc(s.score ?? "--")} 分 · ${esc(s.grade)} 级</span>
                  <span class="text-zinc-400 font-mono text-[11px]">${esc(fmtTime(s.createdAt))}</span>
                </div>
                <span class="py-0.5 px-2 rounded-full font-mono text-[11px] font-semibold ${s.viewCount > 0 ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300" : "bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400"}">浏览 ${s.viewCount} 次</span>
              </div>

              <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1 text-[11.5px] text-zinc-600 dark:text-zinc-400">
                <div class="truncate">创建者 IP：<span class="font-mono text-zinc-900 dark:text-zinc-200">${esc(creatorDesc)}</span></div>
                <div class="truncate">访问统计：<span class="font-mono text-zinc-800 dark:text-zinc-300">${esc(lastViewDesc)}</span></div>
              </div>
            </div>
          </div>

          <div class="px-4 py-2.5 bg-zinc-50/70 border-t border-zinc-950/[0.05] dark:bg-white/[0.02] dark:border-white/[0.06] flex items-center justify-between gap-2 text-xs">
            <button type="button" data-previewshare="${esc(s.id)}" class="py-1 px-2.5 rounded-lg font-semibold bg-zinc-900 text-white hover:bg-zinc-800 transition dark:bg-zinc-100 dark:text-zinc-950">查看完整详情与访客列表</button>
            <div class="flex items-center gap-2">
              <a href="./r/${esc(s.id)}" target="_blank" rel="noopener" class="py-1 px-2.5 rounded-lg font-medium ring-1 ring-zinc-950/[0.1] bg-white text-zinc-700 hover:bg-zinc-100 dark:bg-zinc-800 dark:ring-white/[0.1] dark:text-zinc-200">打开原网页 ↗</a>
            </div>
          </div>
        </article>
      `;
    }).join("");
  }

  function renderUniqueIpsTable(ips) {
    const tbody = $("#ipsTableBody");
    if (!tbody) return;
    const q = STATE.q.trim().toLowerCase();
    const list = q
      ? ips.filter(x => `${x.ip} ${x.cc} ${x.city} ${x.asn} ${x.org} ${x.os} ${x.browser} ${(x.shareIds || []).join(" ")}`.toLowerCase().includes(q))
      : ips;

    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="py-10 text-center text-zinc-400">暂无独立 IP 汇总数据</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(x => {
      const geo = [x.cc ? `${flagEmoji(x.cc)} ${countryName(x.cc)}` : "", x.city, x.asn, x.org].filter(Boolean).join(" · ") || "–";
      const sharesHtml = (x.shareIds || []).length
        ? x.shareIds.map(sid => `<button type="button" data-previewshare="${esc(sid)}" class="py-0.5 px-1.5 rounded font-mono text-[11px] font-semibold bg-emerald-50 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-500/15 dark:text-emerald-300">#${esc(sid)}</button>`).join(" ")
        : `<span class="text-zinc-400">–</span>`;

      return `
        <tr class="hover:bg-zinc-50/80 dark:hover:bg-white/[0.02] transition">
          <td class="py-2.5 px-4 whitespace-nowrap">
            <button type="button" data-filterip="${esc(x.ip)}" class="font-mono font-semibold text-zinc-950 hover:text-blue-600 dark:text-white dark:hover:text-blue-400">${esc(x.ip)}</button>
            <a href="./?ip=${encodeURIComponent(x.ip)}" target="_blank" rel="noopener" class="ms-1.5 text-[10px] text-blue-600 hover:underline dark:text-blue-400">信誉↗</a>
          </td>
          <td class="py-2.5 px-3 max-w-[260px] truncate text-zinc-700 dark:text-zinc-300" title="${esc(geo)}">${esc(geo)}</td>
          <td class="py-2.5 px-3 whitespace-nowrap text-zinc-600 dark:text-zinc-400">${esc([x.os, x.browser].filter(Boolean).join(" · "))}</td>
          <td class="py-2.5 px-3 font-mono whitespace-nowrap">
            <span class="font-semibold text-zinc-900 dark:text-white">${x.scans}</span> 检测 ·
            <span class="text-emerald-600 dark:text-emerald-400">${x.shareViews}</span> 看分享 ·
            <span class="text-purple-600 dark:text-purple-400">${x.shareCreates}</span> 发分享
          </td>
          <td class="py-2.5 px-3 font-mono whitespace-nowrap text-[11px] text-zinc-500 dark:text-zinc-400">${esc(fmtTime(x.firstSeen))} → ${esc(fmtTime(x.lastSeen))}</td>
          <td class="py-2.5 px-4 space-x-1">${sharesHtml}</td>
        </tr>
      `;
    }).join("");
  }

  async function openShareDetailModal(sid) {
    if (!sid) return;
    STATE.currentModalShareId = sid;
    const modal = $("#shareDetailModal");
    const body = $("#mdlBody");
    if (!modal || !body) return;

    $("#mdlShareIdBadge").textContent = `#${sid}`;
    $("#mdlOpenPublicBtn").href = `./r/${encodeURIComponent(sid)}`;
    body.innerHTML = `<div class="py-12 text-center text-zinc-400">正在加载分享快照 #${esc(sid)} 详情…</div>`;
    modal.hidden = false;

    const data = await apiGet(`./api/who/admin/share/${encodeURIComponent(sid)}`);
    if (!data) {
      body.innerHTML = `<div class="py-12 text-center text-rose-500">该分享快照不存在或已被删除</div>`;
      return;
    }

    const rep = data.report || {};
    const meta = data.meta || {};
    const viewers = data.viewers || [];
    const checks = (rep.checks || []).filter(c => c.level === "bad" || c.level === "warn");
    const scenarios = rep.scenarios || [];

    $("#mdlDeleteShareBtn").hidden = !data.exists;

    const cardBlock = data.exists
      ? `<div class="rounded-xl overflow-hidden bg-[#0B0E14] ring-1 ring-zinc-950/[0.1] dark:ring-white/[0.1]">
           <img src="./r/${esc(sid)}.svg" alt="分享卡片 #${esc(sid)}" class="w-full h-auto block aspect-[2/1]">
         </div>`
      : `<div class="rounded-xl p-4 bg-rose-50 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300">该分享内容本体已删除或过期，以下仅保留历史访问轨迹。</div>`;

    const scenHtml = scenarios.length
      ? `
        <div>
          <h4 class="font-semibold text-zinc-900 dark:text-white mb-2">分享页内的六大业务场景评分</h4>
          <div class="grid grid-cols-2 sm:grid-cols-3 gap-2">
            ${scenarios.map(sc => `
              <div class="rounded-xl p-2.5 bg-zinc-50 ring-1 ring-zinc-950/[0.06] dark:bg-white/[0.03] dark:ring-white/[0.07]">
                <div class="flex items-center justify-between font-semibold">
                  <span>${esc(sc.name)}</span>
                  <span class="font-mono ${sc.score >= 80 ? "text-emerald-600 dark:text-emerald-400" : sc.score >= 55 ? "text-amber-600 dark:text-amber-400" : "text-rose-600 dark:text-rose-400"}">${sc.score}%</span>
                </div>
                <div class="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 truncate" title="${esc(sc.reason)}">${esc(sc.reason)}</div>
              </div>
            `).join("")}
          </div>
        </div>`
      : "";

    const issuesHtml = data.exists
      ? `
        <div>
          <h4 class="font-semibold text-zinc-900 dark:text-white mb-2">分享页展示的异常/扣分项 (${checks.length} 项)</h4>
          ${checks.length
            ? `<div class="space-y-1.5">
                ${checks.map(c => `
                  <div class="rounded-lg px-3 py-2 flex items-start gap-2 ${c.level === "bad" ? "bg-rose-50/80 text-rose-900 dark:bg-rose-500/12 dark:text-rose-200" : "bg-amber-50/80 text-amber-950 dark:bg-amber-500/12 dark:text-amber-200"}">
                    <span class="font-mono font-bold shrink-0">[${c.level === "bad" ? "高危" : "可疑"} · ${esc(c.id)}]</span>
                    <span>${esc(c.summary)}</span>
                  </div>
                `).join("")}
               </div>`
            : `<div class="rounded-lg px-3 py-2 bg-emerald-50 text-emerald-800 dark:bg-emerald-500/12 dark:text-emerald-300">✓ 该分享报告全部核心检测项均绿灯通过（0 处异常）</div>`}
        </div>`
      : "";

    const viewerRowsHtml = viewers.length
      ? viewers.map(v => {
          const [lbl, cls] = EVENT_BADGE[v.event] || [v.event, "bg-zinc-100 text-zinc-700"];
          const geo = [v.cc ? `${flagEmoji(v.cc)} ${countryName(v.cc)}` : "", v.city, v.asn, v.org].filter(Boolean).join(" · ") || "–";
          return `
            <tr>
              <td class="py-2 px-3 font-mono whitespace-nowrap text-zinc-500 dark:text-zinc-400">${esc(fmtTime(v.ts))}</td>
              <td class="py-2 px-2 whitespace-nowrap"><span class="py-0.5 px-1.5 rounded text-[10.5px] font-semibold ${cls}">${esc(lbl)}</span></td>
              <td class="py-2 px-2 font-mono font-semibold text-zinc-900 dark:text-white whitespace-nowrap">${esc(v.ip)}</td>
              <td class="py-2 px-2 truncate max-w-[220px] text-zinc-600 dark:text-zinc-300">${esc(geo)}</td>
              <td class="py-2 px-3 truncate max-w-[200px] text-zinc-500 dark:text-zinc-400">${esc([v.os, v.browser].filter(Boolean).join(" · "))}</td>
            </tr>
          `;
        }).join("")
      : `<tr><td colspan="5" class="py-6 text-center text-zinc-400">后台开启后尚无针对该分享页的访问记录</td></tr>`;

    body.innerHTML = `
      ${cardBlock}
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
        <div class="rounded-xl p-3 bg-zinc-50 ring-1 ring-zinc-950/[0.06] dark:bg-white/[0.03] dark:ring-white/[0.07]">
          <div class="text-[11px] text-zinc-500 dark:text-zinc-400">生成时间</div>
          <div class="mt-0.5 font-mono font-semibold text-zinc-900 dark:text-white">${esc(fmtTime(data.createdAt))}</div>
        </div>
        <div class="rounded-xl p-3 bg-zinc-50 ring-1 ring-zinc-950/[0.06] dark:bg-white/[0.03] dark:ring-white/[0.07]">
          <div class="text-[11px] text-zinc-500 dark:text-zinc-400">创建者真实 IP（仅后台可见）</div>
          <div class="mt-0.5 font-mono font-semibold text-zinc-900 dark:text-white truncate">${esc(meta.creatorIp || "上线前存量（未记录）")} ${esc(meta.creatorCity || "")}</div>
        </div>
        <div class="rounded-xl p-3 bg-zinc-50 ring-1 ring-zinc-950/[0.06] dark:bg-white/[0.03] dark:ring-white/[0.07]">
          <div class="text-[11px] text-zinc-500 dark:text-zinc-400">累计被打开次数</div>
          <div class="mt-0.5 font-mono font-semibold text-emerald-600 dark:text-emerald-400">${meta.viewCount ?? 0} 次</div>
        </div>
      </div>
      ${scenHtml}
      ${issuesHtml}
      <div>
        <h4 class="font-semibold text-zinc-900 dark:text-white mb-2">谁生成 / 打开过这个分享页 (${viewers.length} 条记录)</h4>
        <div class="rounded-xl ring-1 ring-zinc-950/[0.06] dark:ring-white/[0.08] overflow-x-auto">
          <table class="w-full text-left border-collapse text-xs">
            <thead>
              <tr class="border-b border-zinc-950/[0.06] bg-zinc-50/80 text-[11px] text-zinc-500 dark:border-white/[0.07] dark:bg-white/[0.02] dark:text-zinc-400">
                <th class="py-2 px-3">时间</th>
                <th class="py-2 px-2">动作</th>
                <th class="py-2 px-2">访客 IP</th>
                <th class="py-2 px-2">归属地与运营商</th>
                <th class="py-2 px-3">终端与浏览器</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-zinc-950/[0.05] dark:divide-white/[0.05]">${viewerRowsHtml}</tbody>
          </table>
        </div>
      </div>
    `;
  }

  function switchTab(tab) {
    STATE.tab = tab;
    $$("#admTabs .adm-tab").forEach(btn => {
      const on = btn.dataset.admtab === tab;
      btn.setAttribute("aria-selected", on ? "true" : "false");
      btn.className = "adm-tab py-2 px-3.5 rounded-lg text-xs transition " + (
        on ? "font-semibold bg-white text-zinc-950 shadow-2xs dark:bg-zinc-800 dark:text-white"
           : "font-medium text-zinc-600 hover:text-zinc-950 dark:text-zinc-400 dark:hover:text-zinc-100"
      );
    });
    $$("[data-admpanel]").forEach(p => { p.hidden = p.dataset.admpanel !== tab; });
    $("#eventFilterPills").hidden = tab !== "visits";
    if (tab === "shares") loadShares();
    if (tab === "ips" && STATE.overview) renderUniqueIpsTable(STATE.overview.topIps || []);
  }

  async function refreshAll() {
    const ov = await apiGet("./api/who/admin/overview?days=30");
    if (!ov) return;
    showDash();
    renderOverview(ov);
    await Promise.all([
      loadVisits(),
      loadShares()
    ]);
    const syncEl = $("#admLastSync");
    if (syncEl) syncEl.textContent = `更新于 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`;
  }

  document.addEventListener("DOMContentLoaded", () => {
    // Theme toggle
    $("#btnAdmTheme")?.addEventListener("click", () => {
      const dark = document.documentElement.classList.toggle("dark");
      try { localStorage.setItem("whoprobe:theme", dark ? "dark" : "light"); } catch (e) {}
    });

    // Login form
    $("#loginForm")?.addEventListener("submit", async e => {
      e.preventDefault();
      const pwd = $("#admPwdInput")?.value || "";
      const btn = $("#btnLoginSubmit");
      if (btn) { btn.disabled = true; btn.textContent = "验证中…"; }
      try {
        const r = await fetch("./api/who/admin/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ password: pwd })
        });
        if (r.status === 429) {
          showLogin("尝试次数过多，请 10 分钟后再试");
        } else if (!r.ok) {
          showLogin("管理口令错误，请重试");
        } else {
          $("#admPwdInput").value = "";
          await refreshAll();
        }
      } catch (err) {
        showLogin("网络异常，请稍后重试");
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = "进入管理后台"; }
      }
    });

    // Logout
    $("#btnAdmLogout")?.addEventListener("click", async () => {
      await fetch("./api/who/admin/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
      showLogin("已安全退出管理会话");
    });

    $("#btnRefreshAdm")?.addEventListener("click", () => {
      refreshAll();
      toast("已刷新最新访问与分享数据");
    });

    // Tabs
    $("#admTabs")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-admtab]");
      if (btn) switchTab(btn.dataset.admtab);
    });

    // Event type filter pills
    $("#eventFilterPills")?.addEventListener("click", e => {
      const btn = e.target.closest("[data-evf]");
      if (!btn) return;
      STATE.event = btn.dataset.evf || "";
      STATE.offset = 0;
      $$("#eventFilterPills .evf-btn").forEach(b => {
        const on = (b.dataset.evf || "") === STATE.event;
        b.className = "evf-btn py-1 px-2.5 rounded-md font-medium transition " + (
          on ? "bg-white text-zinc-950 shadow-2xs dark:bg-zinc-800 dark:text-white" : "text-zinc-600 hover:text-zinc-950 dark:text-zinc-400"
        );
      });
      loadVisits();
    });

    // Search input (debounced)
    let qTimer = null;
    $("#admSearchInput")?.addEventListener("input", e => {
      clearTimeout(qTimer);
      qTimer = setTimeout(() => {
        STATE.q = (e.target.value || "").trim();
        STATE.offset = 0;
        if (STATE.tab === "visits") loadVisits();
        else if (STATE.tab === "shares") loadShares();
        else if (STATE.overview) renderUniqueIpsTable(STATE.overview.topIps || []);
      }, 220);
    });

    // Daily bar chart click -> filter by day
    $("#dailyChartBox")?.addEventListener("click", e => {
      const bar = e.target.closest("[data-daybar]");
      if (!bar) return;
      const d = bar.dataset.daybar;
      STATE.day = STATE.day === d ? "" : d;
      STATE.offset = 0;
      if (STATE.overview) renderOverview(STATE.overview);
      switchTab("visits");
      loadVisits();
    });

    $("#btnClearDayFilter")?.addEventListener("click", () => {
      STATE.day = "";
      STATE.offset = 0;
      if (STATE.overview) renderOverview(STATE.overview);
      loadVisits();
    });

    // Pagination
    $("#btnPrevPage")?.addEventListener("click", () => {
      STATE.offset = Math.max(0, STATE.offset - STATE.limit);
      loadVisits();
    });
    $("#btnNextPage")?.addEventListener("click", () => {
      STATE.offset += STATE.limit;
      loadVisits();
    });

    // Delegated clicks inside main view (preview share, filter IP, copy IP)
    $("#dashView")?.addEventListener("click", e => {
      const prevBtn = e.target.closest("[data-previewshare]");
      if (prevBtn) {
        openShareDetailModal(prevBtn.dataset.previewshare);
        return;
      }
      const fIp = e.target.closest("[data-filterip]");
      if (fIp) {
        const ip = fIp.dataset.filterip;
        $("#admSearchInput").value = ip;
        STATE.q = ip;
        STATE.offset = 0;
        switchTab("visits");
        loadVisits();
        return;
      }
      const cIp = e.target.closest("[data-copyip]");
      if (cIp) {
        copyText(cIp.dataset.copyip, `已复制 IP ${cIp.dataset.copyip}`);
      }
    });

    // Modal controls & delete share
    $("#mdlCloseBtn")?.addEventListener("click", () => { $("#shareDetailModal").hidden = true; });
    $("#shareDetailModal")?.addEventListener("click", e => {
      if (e.target === $("#shareDetailModal")) $("#shareDetailModal").hidden = true;
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && !$("#shareDetailModal").hidden) $("#shareDetailModal").hidden = true;
    });
    $("#mdlDeleteShareBtn")?.addEventListener("click", async () => {
      const sid = STATE.currentModalShareId;
      if (!sid || !confirm(`确定要永久删除分享报告 #${sid} 吗？删除后公开链接将失效。`)) return;
      const r = await fetch(`./api/who/admin/share/${encodeURIComponent(sid)}/delete`, {
        method: "POST",
        credentials: "same-origin"
      });
      if (r.ok) {
        toast(`已删除分享报告 #${sid}`);
        $("#shareDetailModal").hidden = true;
        refreshAll();
      }
    });

    refreshAll();
  });
})();
