const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

// Load the real browser entry point without starting its network probes.
// Only the browser readings and DOM are fixtures; the scoring and probe code run unchanged.
const app = fs.readFileSync(path.join(__dirname, "../static/app.js"), "utf8");
const instrumented = app.replace(/\}\)\(\);\s*$/, `
  globalThis.tests = {
    readWorker: probeWorkerRealm,
    readIframe: probeLiesAndIframe,
    readShared: probeSwRealm,
    readCpu: probeCpuArch,
    updateUdp: updateUdpRttProbe,
    setIceTiming: value => { R.stunRttMs = value; },
    check: evaluateAllChecks,
    score: () => { renderChecksAndScore(); return R.score; },
    read: id => R.values[id],
    setState: state => { R = state; },
    compare: (id, result) => getVisualConflict(id, result),
  };
})();`);
assert.notEqual(instrumented, app, "browser closure to exercise was not found");

function harness({ mainMemory, workerMemory, iframeMemory, mainPlatform = "MacIntel", shared, readings = {}, state = {} } = {}) {
  const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";
  const navigator = Object.create({ userAgent, platform: mainPlatform, language: "en-US", languages: ["en-US"], hardwareConcurrency: 8, deviceMemory: mainMemory });
  const screen = Object.create({ width: 1440, height: 900 });
  const iframe = {
    style: {}, setAttribute() {}, remove() {},
    contentWindow: { navigator: Object.create(navigator, { deviceMemory: { value: iframeMemory } }), screen, Intl, Date }
  };
  const worker = {
    ua: userAgent, plat: navigator.platform, langs: "en-US", hc: 8,
    mem: workerMemory, tz: Intl.DateTimeFormat().resolvedOptions().timeZone, ...readings,
  };
  class Worker {
    set onmessage(callback) { queueMicrotask(() => callback({ data: worker })); }
    terminate() {}
  }
  const nodes = Object.fromEntries([
    "sceneBadge", "topGiveaway", "scoreSub", "issueCount", "cntBad", "cntWarn", "cntOk",
  ].map(id => [`#${id}`, {}]));
  const document = {
    querySelector: key => nodes[key] || null, querySelectorAll: () => [], addEventListener() {},
    createElement: tag => { assert.equal(tag, "iframe"); return iframe; }, body: { appendChild() {} }
  };
  const sandbox = {
    document, navigator, screen, window: { Worker, Blob }, Worker, Blob, URL, Intl,
    location: { hostname: "localhost", href: "http://localhost/", search: "" },
    setTimeout() {}, // the fake worker sends its reply in a microtask; no timeout needs to fire
  };
  if (shared) sandbox.SharedWorker = class {
    port = { start() {}, close() {}, postMessage() { this.onmessage({ data: shared }); } };
  };
  vm.runInNewContext(instrumented, sandbox, { filename: "static/app.js" });
  sandbox.tests.setState({ finished: true, values: {}, ...state });
  return sandbox.tests;
}

for (const [name, mainMemory, workerMemory] of [
  ["on the page", undefined, 8],
  ["in the worker", 8, undefined],
  ["in both contexts", undefined, undefined],
]) {
  test(`unavailable memory ${name} is not a conflict or a successful comparison`, async () => {
    const h = harness({ mainMemory, workerMemory });
    await h.readWorker();
    assert.notEqual(h.check().fpb.level, "bad");
    assert.match(h.read("worker"), /内存/);
    assert.doesNotMatch(h.read("worker"), /完全一致/);
  });
}

test("two different memory values still report a direct mismatch", async () => {
  const h = harness({ mainMemory: 4, workerMemory: 8 });
  await h.readWorker();
  assert.equal(h.check().fpb.level, "bad");
  assert.match(h.read("worker"), /不一致.*内存/);
});

test("a worker response with no comparable fields is not a pass", async () => {
  const h = harness({ readings: { ua: "", plat: "", langs: "", hc: null, mem: null, tz: "" } });
  await h.readWorker();
  assert.match(h.read("worker"), /没有可.*核对|无可.*核对/);
});

test("missing iframe memory is unavailable, but two concrete values can disagree", () => {
  const hidden = harness({ iframeMemory: 8 });
  hidden.readIframe();
  assert.match(hidden.read("iframe"), /未核对：deviceMemory/);
  assert.notEqual(hidden.check().tamper.level, "bad");
  const mismatch = harness({ mainMemory: 4, iframeMemory: 8 });
  mismatch.readIframe();
  assert.match(mismatch.read("iframe"), /读数不符：deviceMemory/);
  assert.equal(mismatch.check().tamper.level, "bad");
});

test("a platform visible only in SharedWorker is not a cross-realm conflict", async () => {
  const h = harness({ mainPlatform: "", shared: { plat: "MacIntel", hc: 8, lang: "en-US" } });
  await h.readShared();
  assert.notEqual(h.check().fpb.level, "bad");
  assert.match(h.read("swrealm"), /已核对 2 项.*未核对/);
});

test("a NaN architecture discrepancy is informational, not an issue", () => {
  // Select the opposite Client Hints value for this JS engine's actual sample.
  const f = new Float32Array(1);
  f[0] = Infinity;
  f[0] = f[0] - f[0];
  const detected = new Uint8Array(f.buffer)[3] === 255 ? "x86" : "arm";
  const state = { finished: true, values: {}, hi: { architecture: detected === "x86" ? "arm" : "x86" } };
  const h = harness({ state });
  const before = h.score();
  h.readCpu();
  assert.equal(h.check().fpb.level, "info");
  assert.match(h.read("cpuarch"), /架构参考|仅供参考|架构推测/);
  assert.equal(h.score(), before);
});

test("an explicit Linux platform and Apple Metal renderer remain a real inconsistency", () => {
  const h = harness({ state: { dev: { os: "Linux" }, gpuRaw: "ANGLE (Apple, ANGLE Metal Renderer: Apple M5)" } });
  const finding = h.check().fpb;
  assert.equal(finding.level, "bad");
  assert.match(finding.summary, /Apple.*Linux/);
  assert.doesNotMatch(finding.summary, /虚拟机硬伤/);
});

test("955 ms HTTP-only is visible without classifying or scoring it as multi-hop", () => {
  const state = { finished: true, values: {}, latDone: true, httpRtt: 955, srvTcpRtt: null };
  for (const geo of [false, true]) {
    const h = harness({ state: geo ? { ...state, ipLat: 13.75, ipLon: 100.5, srvCoords: [35.7, 139.7] } : state });
    const verdict = h.check().rtt;
    assert.equal(verdict.level, "info");
    assert.match(verdict.summary, /955 ms.*延迟偏高.*未.*握手/);
    assert.equal(h.compare("rtt", verdict).single, "延迟偏高");
    const highScore = h.score();
    h.setState({ ...state, httpRtt: 46 });
    assert.equal(h.score(), highScore);
    h.setState({ ...state, httpRtt: 46, srvTcpRtt: 42 });
    assert.equal(h.score(), highScore);
  }
});

test("a fast ICE candidate cannot convert HTTP-only latency into a UDP bypass warning", () => {
  const h = harness({ state: { latDone: true, httpRtt: 955, rtcDone: true } });
  h.setIceTiming(22);
  h.updateUdp();
  assert.match(h.read("udprtt"), /首个公网 ICE 候选 22 ms/);
  assert.equal(h.check().rtt.level, "info");
});

test("a measured TCP vs HTTP gap is still reported, without claiming an exact route", () => {
  const h = harness({ state: { latDone: true, httpRtt: 450, srvTcpRtt: 45 } });
  const verdict = h.check().rtt;
  assert.equal(verdict.level, "bad");
  assert.match(verdict.summary, /450 ms.*45 ms|45 ms.*450 ms/);
  assert.doesNotMatch(verdict.summary, /抓获|实锤/);
});
