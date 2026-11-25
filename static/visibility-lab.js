/* Standalone, user-initiated measurements. All endpoint URLs come from deployment config. */
(function (makeLab) {
  if (typeof module === 'object' && module.exports) {
    module.exports = makeLab;
  } else {
    const lab = makeLab(window);
    window.WhoVisibilityLab = lab.api;
    lab.installSupport();
  }
})(function makeVisibilityLab(win) {
  'use strict';

  const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
  const SAMPLE_PATH = /^(?:\/who)?\/api\/who\/visibility\/sample$/;
  const TOKEN = /^[0-9a-f]{32}$/;
  const PROTOCOL = 'who-visibility-storage/v1';
  const MEDIA = ['cookie', 'localStorage', 'indexedDB'];
  const STORAGE_MAX = 25000;
  const CLEANUP_MS = 1250;
  const UNMEASURED = () => Object.fromEntries(MEDIA.map(name => [name, 'inconclusive']));

  class LabError extends Error {}
  const reasonOf = (err, fallback) => err instanceof LabError ? err.message : fallback;

  function endpoint(value) {
    if (typeof value !== 'string' || value.length > 2048 || !/^https?:\/\/[^/]/i.test(value) || /[\s\\?#]/.test(value)) return null;
    try {
      const url = new URL(value);
      if (url.username || url.password || !url.hostname || url.hostname.endsWith('.')) return null;
      if (url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname))) return url;
    } catch (_) { /* Invalid URL. */ }
    return null;
  }

  function literalIP(value) {
    if (typeof value !== 'string' || value.length > 45) return null;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split('.').every(part => part === String(Number(part)) && Number(part) <= 255)) return value;
    if (value.includes(':') && /^[0-9a-f:.]+$/i.test(value)) {
      try { return new URL(`https://[${value}]/`).hostname.slice(1, -1); } catch (_) { /* Not IPv6. */ }
    }
    return null;
  }

  function siteGroup(url) {
    if (!url) return null;
    const host = url.hostname;
    if (LOOPBACK.has(host) || literalIP(host) || (host.startsWith('[') && literalIP(host.slice(1, -1)))) return host;
    if (!/^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/.test(host) || host.endsWith('.localhost')) return null;
    // Different last two labels prove different registrable domains; equal labels
    // are ambiguous without a PSL (e.g. either example.com or the suffix co.uk).
    return host.split('.').slice(-2).join('.');
  }

  function distinctSites(...urls) {
    const groups = urls.map(siteGroup);
    return groups.every(Boolean) && new Set(groups).size === groups.length;
  }

  function timeoutMs(value, fallback, max) {
    return Number.isFinite(value) && value > 0 ? Math.max(50, Math.min(max, Math.trunc(value))) : fallback;
  }

  function bounded(promise, ms, cancel) {
    let timer;
    const limit = new Promise((_, reject) => {
      timer = setTimeout(() => {
        reject(new LabError('timeout'));
        if (cancel) cancel();
      }, Math.max(0, ms));
    });
    return Promise.race([promise, limit]).finally(() => clearTimeout(timer));
  }

  function nonce() {
    return Array.from(win.crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
  }

  function unavailable(requireGesture = true) {
    if (!win?.isSecureContext || !win.crypto?.getRandomValues) return 'secure-context-required';
    if (requireGesture && win.navigator?.userActivation?.isActive === false) return 'user-activation-required';
    return null;
  }

  function protocolOfVersion(value) {
    if (typeof value !== 'string') return null;
    switch (value.toLowerCase().replace(/^http\//, '')) {
      case '3': case '3.0': return 'h3';
      case '2': case '2.0': return 'h2';
      case '1.0': case '1.1': return 'h1';
      default: return null;
    }
  }

  function sampleResult(data, challenge) {
    if (data?.ok !== true || data.challenge !== challenge) return { status: 'unknown', reason: 'invalid-sample' };
    const ip = literalIP(data.peer?.ip);
    const peer = ip ? { ip, family: ip.includes(':') ? 6 : 4 } : null;
    const wire = data.connection;
    const version = protocolOfVersion(wire?.httpVersion);
    const alpn = typeof wire?.alpn === 'string' ? wire.alpn.toLowerCase() : null;
    const alpnVersion = alpn === 'h3' || /^h3-\d{1,3}$/.test(alpn || '') ? 'h3'
      : alpn === 'h2' ? 'h2' : protocolOfVersion(alpn?.startsWith('http/1.') ? alpn : null);
    const source = wire?.source === 'direct' || wire?.source === 'trusted-edge' ? wire.source : 'unknown';
    const connection = {
      httpVersion: version ? wire.httpVersion : null,
      alpn: alpnVersion ? alpn : null,
      source
    };
    if (source === 'unknown' || !version) return { status: 'unknown', reason: 'unconfirmed-protocol', peer, connection };
    if (alpn && alpn !== 'unknown' && alpnVersion !== version) return { status: 'unknown', reason: 'conflicting-protocol', peer, connection };
    return { status: `confirmed-${version}`, peer, connection };
  }

  async function route(probeURL, opts) {
    // The panel invokes this from a click (or a later step in that click's workflow).
    const unavailableReason = unavailable(false);
    if (unavailableReason) return { status: 'unknown', reason: unavailableReason };
    const url = endpoint(probeURL);
    if (!url || !SAMPLE_PATH.test(url.pathname)) return { status: 'unknown', reason: 'invalid-probe-url' };
    const challenge = nonce();
    url.searchParams.set('challenge', challenge);
    const controller = new AbortController();
    try {
      return await bounded((async () => {
        const response = await win.fetch(url.href, {
          method: 'GET', mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer',
          cache: 'no-store', redirect: 'error', signal: controller.signal
        });
        if (!response.ok) return { status: 'unknown', reason: 'sample-unavailable' };
        return sampleResult(await response.json(), challenge);
      })(), timeoutMs(opts?.timeoutMs, 6500, 12000), () => controller.abort());
    } catch (err) {
      return { status: 'unknown', reason: reasonOf(err, 'sample-unavailable') };
    }
  }

  function turnConfig(config) {
    const urls = typeof config?.urls === 'string' ? [config.urls] : config?.urls;
    if (!Array.isArray(urls) || urls.length < 1 || urls.length > 4 ||
        typeof config.username !== 'string' || !config.username || config.username.length > 512 ||
        typeof config.credential !== 'string' || !config.credential || config.credential.length > 1024 ||
        /[\s\x00-\x1f\x7f]/.test(config.username + config.credential)) return null;
    for (const url of urls) {
      const match = typeof url === 'string' && /^(turns?):(\[[0-9a-f:.]+\]|[a-z0-9-]+(?:\.[a-z0-9-]+)*)(?::([0-9]{1,5}))?(?:\?transport=(udp|tcp))?$/i.exec(url);
      if (!match || url.length > 512 || (match[3] && !(Number(match[3]) >= 1 && Number(match[3]) <= 65535)) ||
          (match[1].toLowerCase() === 'turns' && match[4]?.toLowerCase() === 'udp')) return null;
      try { new URL(`https://${match[2]}/`); } catch (_) { return null; }
    }
    return { urls: [...urls], username: config.username, credential: config.credential };
  }

  function selectedPair(stats) {
    if (typeof stats?.values !== 'function') return null;
    const ids = new Set();
    for (const item of stats.values()) {
      if (item.type === 'transport' && typeof item.selectedCandidatePairId === 'string') ids.add(item.selectedCandidatePairId);
    }
    // Legacy stats may explicitly mark the selected pair. Nomination alone is not selection.
    if (ids.size === 0) for (const item of stats.values()) if (item.type === 'candidate-pair' && item.selected === true) ids.add(item.id);
    if (ids.size !== 1) return null;
    const pair = stats.get(ids.values().next().value);
    if (pair?.type !== 'candidate-pair') return null;
    const candidate = (id, direction) => {
      const row = stats.get(id);
      if (row?.type !== `${direction}-candidate`) return null;
      return {
        type: ['host', 'srflx', 'prflx', 'relay'].includes(row.candidateType) ? row.candidateType : null,
        protocol: ['udp', 'tcp'].includes(row.protocol) ? row.protocol : null,
        relayProtocol: ['udp', 'tcp', 'tls', 'dtls'].includes(row.relayProtocol) ? row.relayProtocol : null,
        ip: literalIP(row.address ?? row.ip)
      };
    };
    return {
      state: ['frozen', 'waiting', 'in-progress', 'failed', 'succeeded'].includes(pair.state) ? pair.state : null,
      local: candidate(pair.localCandidateId, 'local'), remote: candidate(pair.remoteCandidateId, 'remote'),
      rttMs: Number.isFinite(pair.currentRoundTripTime) && pair.currentRoundTripTime >= 0 ? Math.round(pair.currentRoundTripTime * 1000) : null
    };
  }

  async function rtc(config) {
    const unavailableReason = unavailable();
    if (unavailableReason) return { status: 'inconclusive', reason: unavailableReason };
    const iceServer = turnConfig(config);
    if (!iceServer) return { status: 'inconclusive', reason: 'invalid-turn-config' };
    if (typeof win.RTCPeerConnection !== 'function') return { status: 'inconclusive', reason: 'webrtc-unavailable' };
    const deadline = Date.now() + timeoutMs(config?.timeoutMs, 16000, 28000);
    const resources = [], listeners = [];
    const on = (target, name, handler) => {
      target.addEventListener(name, handler);
      listeners.push(() => target.removeEventListener(name, handler));
    };
    try {
      const ice = { iceServers: [iceServer], iceTransportPolicy: 'relay', iceCandidatePoolSize: 0 };
      const a = new win.RTCPeerConnection(ice); resources.push(a);
      const b = new win.RTCPeerConnection(ice); resources.push(b);
      const aChannel = a.createDataChannel('who-visibility'); resources.push(aChannel);
      const token = nonce();
      let abortNegotiation;
      const fail = new Promise((_, reject) => { abortNegotiation = () => reject(new LabError('relay-unavailable')); });
      const relayCandidates = (src, dst) => {
        const pending = [];
        const add = candidate => dst.addIceCandidate(candidate).catch(abortNegotiation);
        on(src, 'icecandidate', ({ candidate }) => {
          if (!candidate || !(candidate.type === 'relay' || (!candidate.type && /\btyp relay(?: |$)/.test(candidate.candidate)))) return;
          if (dst.remoteDescription) add(candidate); else pending.push(candidate);
        });
        on(src, 'iceconnectionstatechange', () => { if (src.iceConnectionState === 'failed') abortNegotiation(); });
        return () => pending.splice(0).forEach(add);
      };
      const flushA = relayCandidates(a, b), flushB = relayCandidates(b, a);
      let bChannel;
      const echoed = new Promise(resolve => {
        on(b, 'datachannel', ({ channel }) => {
          resources.push(channel);
          if (bChannel || channel.label !== 'who-visibility') { channel.close(); return; }
          bChannel = channel;
          on(channel, 'message', ({ data }) => {
            if (data === token) {
              try { channel.send(`echo:${token}`); } catch (_) { abortNegotiation(); }
            }
          });
        });
        on(aChannel, 'message', ({ data }) => { if (data === `echo:${token}`) resolve(); });
        on(aChannel, 'open', () => {
          try { aChannel.send(token); } catch (_) { abortNegotiation(); }
        });
      });
      const negotiate = (async () => {
        const offer = await a.createOffer();
        await a.setLocalDescription(offer);
        await b.setRemoteDescription(offer); flushA();
        const answer = await b.createAnswer();
        await b.setLocalDescription(answer);
        await a.setRemoteDescription(answer); flushB();
        await echoed;
      })();
      await bounded(Promise.race([negotiate, fail]), deadline - Date.now());
      const stats = async (pc) => {
        try { return selectedPair(await bounded(pc.getStats(), Math.min(1100, deadline - Date.now()))); }
        catch (_) { return null; } // The nonce round trip is still a positive measurement.
      };
      const [aPair, bPair] = await Promise.all([stats(a), stats(b)]);
      if ([aPair, bPair].some(pair => (pair?.local?.type && pair.local.type !== 'relay') ||
          ['host', 'srflx'].includes(pair?.remote?.type))) {
        // No candidate addresses are useful if the relay-only invariant is contradicted.
        return { status: 'inconclusive', reason: 'unexpected-candidate' };
      }
      return { status: 'connected', ...(!aPair || !bPair ? { reason: 'stats-unavailable' } : {}), selected: { a: aPair, b: bPair } };
    } catch (err) {
      return { status: 'inconclusive', reason: reasonOf(err, 'negotiation-failed') };
    } finally {
      listeners.reverse().forEach(dispose => dispose());
      for (const resource of resources.reverse()) {
        try { resource.close(); } catch (_) { /* Already closed. */ }
      }
    }
  }

  const wireMessage = (type, token, extra) => ({ protocol: PROTOCOL, type, nonce: token, ...extra });
  function authentic(event, source, origin, type, token) {
    const d = event.data;
    return event.source === source && event.origin === origin && d?.protocol === PROTOCOL && d.type === type
      && typeof d.nonce === 'string' && (token === null ? TOKEN.test(d.nonce) : d.nonce === token);
  }

  function exchange(source, origin, type, token, until, send) {
    let stop;
    const response = new Promise((resolve, reject) => {
      const message = event => { if (authentic(event, source, origin, type, token)) resolve(event.data); };
      win.addEventListener('message', message);
      stop = () => win.removeEventListener('message', message);
      try { if (send) send(); } catch (err) { reject(err); }
    });
    return bounded(response, until - Date.now()).finally(stop);
  }

  function mountFrame(url, token, deadline, expiry) {
    const node = win.document.createElement('iframe');
    node.hidden = true;
    node.referrerPolicy = 'no-referrer';
    node.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    const loaded = new Promise(resolve => node.addEventListener('load', resolve, { once: true }));
    node.src = url.href;
    win.document.body.append(node);
    const ready = () => bounded(loaded, deadline - Date.now());
    return {
      ready,
      async sample() {
        await ready();
        return exchange(node.contentWindow, url.origin, 'frame-result', token, deadline + CLEANUP_MS,
          () => node.contentWindow.postMessage(wireMessage('frame-sample', token, { expiry }), url.origin));
      },
      async clean(check) {
        const until = Date.now() + CLEANUP_MS;
        await bounded(loaded, until - Date.now());
        return exchange(node.contentWindow, url.origin, 'frame-cleaned', token, until,
          () => node.contentWindow.postMessage(wireMessage('frame-clean', token, { check }), url.origin));
      },
      remove: () => node.remove()
    };
  }

  function mediaStatus(a, b, finalA, cleanB) {
    if (finalA?.cleaned !== true || cleanB?.cleaned !== true) return 'inconclusive';
    if (a === 'blocked' || b?.control === 'blocked' || b?.observed === 'blocked') return 'blocked';
    if (a !== 'ok' || b?.control !== 'ok' || finalA.retained !== true) return 'inconclusive';
    if (b.observed === 'present') return 'shared';
    if (b.observed === 'absent') return 'partitioned';
    return 'inconclusive';
  }

  async function storage(config) {
    const noResult = reason => ({ status: 'inconclusive', reason, media: UNMEASURED() });
    const unavailableReason = unavailable();
    if (unavailableReason) return noResult(unavailableReason);
    const a = endpoint(win.location.origin), b = endpoint(config?.peerURL), frameURL = endpoint(config?.frameURL);
    if (!a || !b || !frameURL || win.top !== win) return noResult('invalid-storage-endpoints');
    if (!distinctSites(a, b, frameURL)) return noResult('site-boundaries-unverified');
    const token = nonce();
    const deadline = Date.now() + timeoutMs(config?.timeoutMs, 14000, STORAGE_MAX);
    const expiry = deadline + CLEANUP_MS;
    let popup, frame;
    try {
      // Opening must happen within the click handler, before the first await.
      popup = win.open('about:blank', '_blank', 'popup');
      if (!popup || popup.closed) return noResult('popup-unavailable');
      const ready = await exchange(popup, b.origin, 'bridge-ready', null, deadline, () => {
        const link = popup.document.createElement('a');
        link.href = b.href;
        link.referrerPolicy = 'no-referrer';
        popup.document.body.append(link);
        link.click(); // Keep opener, without sending the main page as a referrer.
      });
      // Load both copies of the frame before writing A's cookie. No follow-up
      // frame navigation or resource load is needed to read it from B.
      frame = mountFrame(frameURL, token, deadline, expiry);
      await exchange(popup, b.origin, 'bridge-armed', token, deadline, () => {
        popup.postMessage(wireMessage('bridge-arm', token, { readyNonce: ready.nonce, deadline, expiry }), b.origin);
      });
      const sampleA = await frame.sample();
      if (Date.now() >= deadline) return noResult('timeout');
      const sampleB = await exchange(popup, b.origin, 'bridge-result', token, deadline + CLEANUP_MS * 2, () => {
        popup.postMessage(wireMessage('bridge-sample', token), b.origin);
      });
      const cleanA = await frame.clean(true);
      frame.remove(); frame = null;
      const media = Object.fromEntries(MEDIA.map(name => [name, mediaStatus(sampleA?.controls?.[name],
        sampleB?.observations?.[name], cleanA?.cleanup?.[name], sampleB?.cleanup?.[name])]));
      return Object.values(media).some(value => value !== 'inconclusive')
        ? { status: 'measured', media }
        : noResult(sampleB.reason === 'timeout' ? 'timeout' : 'storage-evidence-incomplete');
    } catch (err) {
      return noResult(reasonOf(err, 'storage-unavailable'));
    } finally {
      if (frame) {
        try { await frame.clean(false); } catch (_) { /* The frame also expires and handles pagehide. */ }
        frame.remove();
      }
      if (popup) popup.close();
    }
  }

  const storageName = role => `who_visibility_lab_v1_${role}`;
  const blocked = err => ['SecurityError', 'NotAllowedError', 'QuotaExceededError'].includes(err?.name);
  const fresh = value => typeof value === 'string' && /^[0-9a-f]{32}\.\d{13}$/.test(value) && Number(value.split('.')[1]) > Date.now();

  // Reserved names contain no per-user ID. The sole value expires logically even after a crash;
  // only this run's live marker can match, and stale values can be replaced at the next opt-in.
  function idbOpen(name, create, live) {
    return new Promise((resolve, reject) => {
      let aborted = false, settled = false;
      const req = win.indexedDB.open(name, 1);
      req.onupgradeneeded = () => {
        if (settled || !create || !live()) { aborted = true; req.transaction.abort(); }
        else req.result.createObjectStore('marker');
      };
      req.onblocked = () => { settled = true; reject(new Error('open blocked')); };
      req.onerror = () => { if (aborted) resolve(null); else reject(req.error); };
      req.onsuccess = () => { if (settled) req.result.close(); else resolve(req.result); };
    });
  }

  async function idbOp(role, mode, marker, live = () => true) {
    const name = storageName(role);
    let db;
    try { db = await idbOpen(name, mode === 'write', live); }
    catch (err) {
      if (mode === 'remove') return idbDelete(name); // The lab owns this reserved DB exclusively.
      throw err;
    }
    if (!db) return mode === 'read' ? null : mode === 'remove';
    let value;
    try {
      value = await new Promise((resolve, reject) => {
        const tx = db.transaction('marker', mode === 'read' ? 'readonly' : 'readwrite');
        const store = tx.objectStore('marker');
        const req = store.get('slot');
        let result;
        req.onsuccess = () => {
          const previous = req.result ?? null;
          if (mode === 'read') result = previous;
          if (mode === 'write') {
            result = live() && !fresh(previous);
            if (result) store.put(marker, 'slot');
          }
          if (mode === 'remove') {
            result = previous === marker || !fresh(previous);
            if (result) store.delete('slot');
          }
        };
        tx.oncomplete = () => resolve(result);
        tx.onabort = tx.onerror = () => reject(tx.error || new Error('transaction failed'));
      });
    } catch (err) {
      if (mode !== 'remove') throw err;
      value = true; // Try dropping the reserved DB even if verifying the marker failed.
    } finally { db.close(); }
    if (mode !== 'remove') return value;
    // A fresh different marker means another run owns this slot; do not delete its DB.
    return value ? idbDelete(name) : true;
  }

  async function idbDelete(name) {
    await new Promise((resolve, reject) => {
      const req = win.indexedDB.deleteDatabase(name);
      req.onsuccess = resolve;
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('delete blocked'));
    });
    return true;
  }

  function guardedRemove(read, erase, marker) {
    let previous;
    try { previous = read(); }
    catch (_) {
      // Only the reserved lab slot is affected. If readback lost permission
      // after a write, still attempt removal without reporting it as verified.
      erase();
      return false;
    }
    if (previous === marker) erase();
    return read() !== marker;
  }

  function storageAdapters() {
    const cookieName = role => `__Host-${storageName(role)}`;
    const cookieRead = role => {
      const prefix = `${cookieName(role)}=`;
      const row = win.document.cookie.split(/;\s*/).find(item => item.startsWith(prefix));
      return row === undefined ? null : row.slice(prefix.length);
    };
    const cookieWrite = (role, marker, age) => {
      win.document.cookie = `${cookieName(role)}=${marker}; Path=/; Max-Age=${age}; SameSite=None; Secure`;
    };
    return {
      cookie: {
        read: cookieRead,
        write(role, marker, live, expiry) { if (live()) cookieWrite(role, marker, Math.ceil((expiry - Date.now()) / 1000)); },
        remove: (role, marker) => guardedRemove(() => cookieRead(role), () => cookieWrite(role, '', 0), marker)
      },
      localStorage: {
        read: role => win.localStorage.getItem(storageName(role)),
        write(role, marker, live) { if (live()) win.localStorage.setItem(storageName(role), marker); },
        remove: (role, marker) => guardedRemove(() => win.localStorage.getItem(storageName(role)),
          () => win.localStorage.removeItem(storageName(role)), marker)
      },
      indexedDB: {
        read: role => idbOp(role, 'read'),
        write: (role, marker, live) => idbOp(role, 'write', marker, live),
        remove: (role, marker) => idbOp(role, 'remove', marker)
      }
    };
  }

  function installSupport() {
    const config = win.document.documentElement.dataset;
    const a = endpoint(config.visibilityAOrigin), b = endpoint(config.visibilityBOrigin), frameURL = endpoint(config.visibilityFrameUrl);
    if (!win.isSecureContext || !a || !b || !frameURL || a.pathname !== '/' || b.pathname !== '/' || !distinctSites(a, b, frameURL)) return;

    if (win.top === win && win.location.origin === b.origin && win.opener) {
      const opener = win.opener, ready = nonce();
      const start = async event => {
        if (!authentic(event, opener, a.origin, 'bridge-arm', null) || event.data.readyNonce !== ready) return;
        const { nonce: token, deadline, expiry } = event.data;
        if (!Number.isSafeInteger(deadline) || deadline <= Date.now() || expiry !== deadline + CLEANUP_MS || !validExpiry(expiry)) return;
        win.removeEventListener('message', start);
        let frame, payload, sampling = false;
        try {
          frame = mountFrame(frameURL, token, deadline, expiry);
          await frame.ready();
          await exchange(opener, a.origin, 'bridge-sample', token, deadline, () => {
            opener.postMessage(wireMessage('bridge-armed', token), a.origin);
          });
          sampling = true;
          payload = await frame.sample(); // Frame B cleans its own control before responding.
        } catch (err) {
          payload = { reason: reasonOf(err, 'frame-unavailable') };
          if (sampling) try { await frame.clean(false); } catch (_) { /* Frame expiration also cleans. */ }
        } finally { if (frame) frame.remove(); }
        opener.postMessage(wireMessage('bridge-result', token, { observations: payload.observations, cleanup: payload.cleanup, reason: payload.reason }), a.origin);
      };
      win.addEventListener('message', start);
      opener.postMessage(wireMessage('bridge-ready', ready), a.origin);
      return;
    }

    if (win.top === win || win.parent !== win.top || win.location.href !== frameURL.href) return;
    const parent = win.parent;
    let session;
    win.addEventListener('message', async event => {
      const role = event.origin === a.origin ? 'a' : event.origin === b.origin ? 'b' : null;
      if (!role) return;
      if (!session && authentic(event, parent, event.origin, 'frame-sample', null) && validExpiry(event.data.expiry)) {
        session = runInFrame(role, event.data.nonce, event.data.expiry);
        const result = await session.sample;
        parent.postMessage(wireMessage('frame-result', session.token, result), event.origin);
      } else if (session?.role === role && authentic(event, parent, event.origin, 'frame-clean', session.token)) {
        const cleanup = await session.clean(event.data.check === true);
        parent.postMessage(wireMessage('frame-cleaned', session.token, { cleanup }), event.origin);
      }
    });
    win.addEventListener('pagehide', () => { if (session) session.clean(false); }, { once: true });
  }

  function validExpiry(expiry) {
    return Number.isSafeInteger(expiry) && expiry > Date.now() && expiry <= Date.now() + STORAGE_MAX + CLEANUP_MS;
  }

  function runInFrame(role, token, expiry) {
    const marker = `${token}.${expiry}`, adapters = storageAdapters(), attempted = new Set();
    let stopping = false, cleaning;
    const live = () => !stopping && Date.now() < expiry;
    const entries = async callback => Object.fromEntries(await Promise.all(MEDIA.map(async name => [name, await callback(adapters[name], name)])));
    const timer = setTimeout(() => clean(false), expiry - Date.now());
    function clean(check) {
      if (cleaning) return cleaning;
      stopping = true;
      clearTimeout(timer);
      cleaning = entries(async (adapter, name) => {
        if (!attempted.has(name)) return { retained: false, cleaned: true };
        let retained = false;
        if (check) try { retained = Date.now() < expiry && (await adapter.read(role)) === marker; } catch (_) { /* No positive control. */ }
        try { return { retained, cleaned: (await adapter.remove(role, marker)) === true }; }
        catch (_) { return { retained, cleaned: false }; }
      });
      return cleaning;
    }
    const sample = (async () => {
      const observations = await entries(async (adapter, name) => {
        let observed;
        if (role === 'b') {
          try {
            const before = await adapter.read('a');
            observed = before === marker ? 'present' : !fresh(before) ? 'absent' : 'other';
          } catch (err) { observed = blocked(err) ? 'blocked' : 'error'; }
        }
        let control = 'inconclusive';
        try {
          if (!fresh(await adapter.read(role)) && live()) {
            // A successful write followed by a failed read must still be cleaned.
            attempted.add(name);
            const written = await adapter.write(role, marker, live, expiry);
            if (written !== false && live()) {
              const after = await adapter.read(role);
              control = after === marker ? 'ok' : !fresh(after) ? 'blocked' : 'inconclusive';
            }
          }
        } catch (err) { if (blocked(err)) control = 'blocked'; }
        return { control, observed };
      });
      if (role === 'a') return { controls: Object.fromEntries(MEDIA.map(name => [name, observations[name].control])) };
      return { observations, cleanup: await clean(false) };
    })();
    return { role, token, sample, clean };
  }

  return {
    api: Object.freeze({ route, rtc, storage }), installSupport,
    helpers: { endpoint, distinctSites, sampleResult, turnConfig, selectedPair, authentic, mediaStatus, runInFrame }
  };
});
