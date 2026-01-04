/**
 * ioBroker JavaScript – CareLink (Auth0)
 * - Pollt /display/message
 * - Schreibt ausgewählte JSON-Teile nach 0_userdata.0.carelink.data.* (nur bei Änderung)
 * - Filter:
 *    - sgs komplett ignorieren (wir nutzen lastSG separat)
 *    - markers: nur den LETZTEN Marker schreiben (unter ...markers.0.*)
 * - Komfort-DPs bleiben wie vorher:
 *    - glucose_mgdl/mmol, delta_mgdl, trend (letzter vs. vorletzter), timestamp
 *    - valid (false bei API-Fehlern oder timestamp älter als 15 min)
 *    - last_valid_update (Zeitpunkt, wann zuletzt ein gültiger Glukosewert übernommen wurde)
 *
 * Auth (einmalig aus logindata.json in diese DPs kopieren):
 *  0_userdata.0.carelink.auth.access_token
 *  0_userdata.0.carelink.auth.refresh_token
 *  0_userdata.0.carelink.auth.client_id
 *  0_userdata.0.carelink.auth.client_secret   (kann leer sein)
 *  0_userdata.0.carelink.auth.audience
 *  0_userdata.0.carelink.auth.token_url       (z.B. https://carelink-login.minimed.eu/oauth/token)
 *
 * Config (empfohlen):
 *  0_userdata.0.carelink.cfg.patientId
 *  0_userdata.0.carelink.cfg.role   ("patient")
 */

const axios = require("axios");

// =====================
// Konfiguration
// =====================
const BASE = "0_userdata.0.carelink";

const CFG = {
  pollSeconds: 60,
  proactiveRefreshMin: 45,
  httpTimeoutMs: 30000,
  validMaxAgeMin: 15,

  // Schutz: maximale Leaf-Updates pro Poll (nur "set" zählt, createState nicht)
  maxLeafSetsPerPoll: 500,
};

const DP = {
  auth: {
    access: `${BASE}.auth.access_token`,
    refresh: `${BASE}.auth.refresh_token`,
    clientId: `${BASE}.auth.client_id`,
    clientSecret: `${BASE}.auth.client_secret`,
    audience: `${BASE}.auth.audience`,
    tokenUrl: `${BASE}.auth.token_url`,
    lastRefreshTs: `${BASE}.auth.last_refresh_ts`,
  },
  cfg: {
    baseCareLink: `${BASE}.cfg.baseUrlCareLink`,
    baseCumulus: `${BASE}.cfg.baseUrlCumulus`,
    discoveryUrl: `${BASE}.cfg.discovery_url`,
    username: `${BASE}.cfg.username`,
    role: `${BASE}.cfg.role`,
    patientId: `${BASE}.cfg.patientId`,
  },
  data: {
    // Komfort-DPs (wie vorher)
    mgdl: `${BASE}.data.glucose_mgdl`,
    mmol: `${BASE}.data.glucose_mmol`,
    delta: `${BASE}.data.delta_mgdl`,
    trend: `${BASE}.data.trend`,
    ts: `${BASE}.data.timestamp`,
    valid: `${BASE}.data.valid`,
    lastValidUpdate: `${BASE}.data.last_valid_update`,
  },
  status: {
    ok: `${BASE}.status.last_ok`,
    err: `${BASE}.status.last_error`,
    code: `${BASE}.status.http_code`,
    lastUrl: `${BASE}.status.last_url`,
    lastBody: `${BASE}.status.last_body`,
    lastJson: `${BASE}.status.last_json`, // gekürzt
    writes: `${BASE}.status.last_write_count`,
  },
  internal: {
    prevMgdl: `${BASE}.internal.prev_mgdl`,
    prevTs: `${BASE}.internal.prev_timestamp`,
    lastPollOk: `${BASE}.internal.last_poll_ok`,
  },
};

const DEFAULT_DISCOVERY = "https://clcloud.minimed.eu/connect/carepartner/v13/discover/android/3.6";

// =====================
// Helper: States
// =====================
function ensureState(id, def, common) {
  if (!existsState(id)) {
    createState(id, def, {
      name: common?.name || id,
      type: common?.type || (typeof def),
      role: common?.role || "state",
      read: true,
      write: true,
    });
  }
}

function s(id) {
  const st = getState(id);
  return st ? st.val : null;
}

function setS(id, val, ack = true) {
  setState(id, { val, ack });
}

function setIfChanged(id, val, ack = true) {
  const st = getState(id);
  if (!st) {
    setState(id, { val, ack });
    return true;
  }
  // Vergleich robust (stringify für non-primitive)
  const a = st.val;
  const b = val;
  if (a === b) return false;

  // handle null/undefined equivalence
  if ((a === null || a === undefined || a === "") && (b === null || b === undefined || b === "")) return false;

  // number/string cross-compare (ioBroker kann number als string liefern bei mixed)
  if (typeof a !== typeof b) {
    if (String(a) === String(b)) return false;
  }

  setState(id, { val, ack });
  return true;
}

function uaHeaders() {
  return { "Accept": "application/json", "User-Agent": "Mozilla/5.0" };
}

function nowMs() {
  return Date.now();
}

function isTimestampValid(tsIso, maxAgeMin) {
  const t = Date.parse(String(tsIso || ""));
  if (!t) return false;
  return (Date.now() - t) <= (maxAgeMin * 60 * 1000);
}

function trendFromDelta(delta) {
  if (delta == null || isNaN(delta)) return "";
  if (delta >= 3) return "↑";
  if (delta <= -3) return "↓";
  return "→";
}

// ioBroker-kompatibles Form-Encoding (kein URLSearchParams)
function buildForm(data) {
  return Object.keys(data)
    .filter(k => data[k] !== undefined && data[k] !== null && data[k] !== "")
    .map(k => encodeURIComponent(k) + "=" + encodeURIComponent(data[k]))
    .join("&");
}

// ioBroker IDs: keine Sonderzeichen/Spaces/Slashes/..
// Wir ersetzen alles außer [a-zA-Z0-9_-] mit "_"
function sanitizeKey(k) {
  return String(k).replace(/[^a-zA-Z0-9_-]/g, "_");
}

// =====================
// Discovery
// =====================
async function loadDiscoveryBasesIfNeeded() {
  let baseCareLink = String(s(DP.cfg.baseCareLink) || "");
  let baseCumulus = String(s(DP.cfg.baseCumulus) || "");

  if (baseCareLink && baseCumulus) return { baseCareLink, baseCumulus };

  const discoveryUrl = String(s(DP.cfg.discoveryUrl) || DEFAULT_DISCOVERY);
  const resp = await axios.get(discoveryUrl, { headers: uaHeaders(), timeout: CFG.httpTimeoutMs });
  const disc = resp.data;

  const cp = disc?.CP;
  if (!Array.isArray(cp)) throw new Error("Discovery: CP fehlt/kein Array");

  const picked = cp.find((c) => String(c.region).toUpperCase() === "EU");
  if (!picked) throw new Error("Discovery: EU region nicht gefunden");

  baseCareLink = picked.baseUrlCareLink;
  baseCumulus = picked.baseUrlCumulus;

  if (!baseCareLink || !baseCumulus) throw new Error("Discovery: baseUrlCareLink/baseUrlCumulus fehlt");

  setS(DP.cfg.baseCareLink, baseCareLink);
  setS(DP.cfg.baseCumulus, baseCumulus);

  return { baseCareLink, baseCumulus };
}

// =====================
// Auth0 Refresh
// =====================
function shouldRefreshProactively() {
  const last = Number(s(DP.auth.lastRefreshTs) || 0);
  if (!last) return true;
  return (nowMs() - last) > (CFG.proactiveRefreshMin * 60 * 1000);
}

async function refreshTokenAuth0() {
  const tokenUrl = String(s(DP.auth.tokenUrl) || "");
  const refresh = String(s(DP.auth.refresh) || "");
  const clientId = String(s(DP.auth.clientId) || "");
  const clientSecret = String(s(DP.auth.clientSecret) || "");
  const audience = String(s(DP.auth.audience) || "");

  if (!tokenUrl || !refresh || !clientId) {
    throw new Error("Auth0 refresh: token_url / refresh_token / client_id fehlt");
  }

  const body = buildForm({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: refresh,
    client_secret: clientSecret || undefined, // kann leer sein
    audience: audience || undefined,
  });

  const headers = { ...uaHeaders(), "Content-Type": "application/x-www-form-urlencoded" };

  let resp;
  try {
    resp = await axios.post(tokenUrl, body, { headers, timeout: CFG.httpTimeoutMs });
  } catch (e) {
    const code = e?.response?.status || 0;
    const data = e?.response?.data
      ? (typeof e.response.data === "string" ? e.response.data : JSON.stringify(e.response.data))
      : "";
    throw new Error(`Auth0 refresh failed HTTP ${code}: ${String(data).slice(0, 500)}`);
  }

  const data = resp.data || {};
  if (!data.access_token) throw new Error("Auth0 refresh: keine access_token im Response");

  setS(DP.auth.access, data.access_token);
  if (data.refresh_token) setS(DP.auth.refresh, data.refresh_token);
  setS(DP.auth.lastRefreshTs, nowMs());
}

// =====================
// CareLink API
// =====================
async function carelinkGet(url) {
  const access = String(s(DP.auth.access) || "");
  if (!access) throw new Error("access_token fehlt");
  return axios.get(url, { headers: { ...uaHeaders(), "Authorization": `Bearer ${access}` }, timeout: CFG.httpTimeoutMs });
}

async function carelinkPostJson(url, bodyObj) {
  const access = String(s(DP.auth.access) || "");
  if (!access) throw new Error("access_token fehlt");
  return axios.post(url, JSON.stringify(bodyObj), {
    headers: { ...uaHeaders(), "Authorization": `Bearer ${access}`, "Content-Type": "application/json" },
    timeout: CFG.httpTimeoutMs,
  });
}

async function ensureIdentity(baseCareLink) {
  const usernameDp = String(s(DP.cfg.username) || "");
  const roleDp = String(s(DP.cfg.role) || "patient");
  const patientIdDp = String(s(DP.cfg.patientId) || "");

  let username = usernameDp;
  if (!username) {
    const meResp = await carelinkGet(`${baseCareLink}/users/me`);
    const me = meResp.data || {};
    username = me.username || me.email || "";
    if (!username) throw new Error("/users/me: username nicht gefunden");
    setS(DP.cfg.username, username);
  }

  if (!patientIdDp) throw new Error("patientId fehlt. Bitte 0_userdata.0.carelink.cfg.patientId setzen.");

  setS(DP.cfg.role, roleDp);
  return { username, role: roleDp, patientId: patientIdDp };
}

// =====================
// JSON → Datenpunkte (rekursiv, nur bei Änderung)
// Filter:
//  - skipKey 'sgs' komplett
//  - key 'markers' => nur letzter Eintrag (als .0)
//  - key 'notificationHistory' => nur letzter Eintrag (als .0)
// =====================
function leafType(v) {
  if (v === null) return "mixed";
  if (Array.isArray(v)) return "string";
  const t = typeof v;
  if (t === "boolean" || t === "number" || t === "string") return t;
  return "string";
}

function normalizeLeaf(v) {
  if (v === undefined) return null;
  if (v === null) return null;
  if (typeof v === "number" && !isFinite(v)) return null;
  if (typeof v === "object") return JSON.stringify(v);
  return v;
}

function ensureLeaf(id, v) {
  const t = leafType(v);
  if (!existsState(id)) {
    let def;
    if (t === "boolean") def = false;
    else if (t === "number") def = 0;
    else def = "";
    createState(id, def, { name: id, type: t, role: "state", read: true, write: true });
  }
}

function writeJsonToStatesFiltered(baseId, obj) {
  let sets = 0;
  const maxSets = Number(CFG.maxLeafSetsPerPoll || 0);

  function setLeaf(pathId, value) {
    if (maxSets > 0 && sets >= maxSets) return;
    ensureLeaf(pathId, value);
    const v = normalizeLeaf(value);
    const changed = setIfChanged(pathId, v);
    if (changed) sets++;
  }

  function walk(pathId, value, keyNameForFilters) {
    if (maxSets > 0 && sets >= maxSets) return;

    if (value === null || value === undefined) {
      setLeaf(pathId, null);
      return;
    }

    if (Array.isArray(value)) {
      // special: markers / notificationHistory => nur den letzten (als .0) + __len=1
      const keyLower = String(keyNameForFilters || "").toLowerCase();
      if (keyLower === "markers" || keyLower === "notificationhistory") {
        const last = value.length > 0 ? value[value.length - 1] : null;
        setLeaf(`${pathId}.__len`, value.length > 0 ? 1 : 0);
        if (value.length > 0) walk(`${pathId}.0`, last, null);
        return;
      }

      // Default: Arrays rekursiv, aber nur bei Änderung setzen
      setLeaf(`${pathId}.__len`, value.length);
      for (let i = 0; i < value.length; i++) {
        walk(`${pathId}.${i}`, value[i], null);
        if (maxSets > 0 && sets >= maxSets) return;
      }
      return;
    }

    if (typeof value === "object") {
      for (const [k, v] of Object.entries(value)) {
        const rawKey = String(k);
        const low = rawKey.toLowerCase();

        // skip sgs komplett
        if (low === "sgs") continue;

        const safe = sanitizeKey(rawKey);
        walk(`${pathId}.${safe}`, v, rawKey);
        if (maxSets > 0 && sets >= maxSets) return;
      }
      return;
    }

    // primitive
    setLeaf(pathId, value);
  }

  walk(baseId, obj, null);
  return sets;
}

// =====================
// Komfort: Glukose extrahieren (lastSG)
// =====================
function extractGlucose(recent) {
  const pd = recent?.patientData || {};
  const lastSG = pd?.lastSG || null;

  const mgdl = (lastSG && lastSG.sg != null) ? Number(lastSG.sg) : null;
  const ts = (lastSG && lastSG.timestamp) ? String(lastSG.timestamp) : "";
  const mmol = (mgdl != null && isFinite(mgdl)) ? Number((mgdl * 0.0555).toFixed(2)) : null;

  return { mgdl, mmol, ts };
}

function updateValidFromCurrentState() {
  const ts = String(s(DP.data.ts) || "");
  const lastOk = Boolean(s(DP.internal.lastPollOk));
  const valid = lastOk && isTimestampValid(ts, CFG.validMaxAgeMin);
  setS(DP.data.valid, valid);
}

// =====================
// Init
// =====================
function initStates() {
  // auth
  ensureState(DP.auth.access, "", { type: "string" });
  ensureState(DP.auth.refresh, "", { type: "string" });
  ensureState(DP.auth.clientId, "", { type: "string" });
  ensureState(DP.auth.clientSecret, "", { type: "string" });
  ensureState(DP.auth.audience, "", { type: "string" });
  ensureState(DP.auth.tokenUrl, "", { type: "string" });
  ensureState(DP.auth.lastRefreshTs, 0, { type: "number" });

  // cfg
  ensureState(DP.cfg.discoveryUrl, DEFAULT_DISCOVERY, { type: "string" });
  ensureState(DP.cfg.baseCareLink, "", { type: "string" });
  ensureState(DP.cfg.baseCumulus, "", { type: "string" });
  ensureState(DP.cfg.username, "", { type: "string" });
  ensureState(DP.cfg.role, "patient", { type: "string" });
  ensureState(DP.cfg.patientId, "", { type: "string" });

  // comfort
  ensureState(DP.data.mgdl, 0, { type: "number" });
  ensureState(DP.data.mmol, 0, { type: "number" });
  ensureState(DP.data.delta, 0, { type: "number" });
  ensureState(DP.data.trend, "", { type: "string" });
  ensureState(DP.data.ts, "", { type: "string" });
  ensureState(DP.data.valid, false, { type: "boolean" });
  ensureState(DP.data.lastValidUpdate, "", { type: "string" });

  // status
  ensureState(DP.status.ok, "", { type: "string" });
  ensureState(DP.status.err, "", { type: "string" });
  ensureState(DP.status.code, 0, { type: "number" });
  ensureState(DP.status.lastUrl, "", { type: "string" });
  ensureState(DP.status.lastBody, "", { type: "string" });
  ensureState(DP.status.lastJson, "", { type: "string" });
  ensureState(DP.status.writes, 0, { type: "number" });

  // internal
  ensureState(DP.internal.prevMgdl, 0, { type: "number" });
  ensureState(DP.internal.prevTs, "", { type: "string" });
  ensureState(DP.internal.lastPollOk, false, { type: "boolean" });
}

// =====================
// Poll
// =====================
async function pollOnce() {
  try {
    setS(DP.status.err, "");
    setS(DP.status.code, 0);
    setS(DP.status.lastUrl, "");
    setS(DP.status.lastBody, "");

    if (shouldRefreshProactively()) {
      await refreshTokenAuth0();
    }

    const { baseCareLink, baseCumulus } = await loadDiscoveryBasesIfNeeded();
    const identity = await ensureIdentity(baseCareLink);

    const url = `${baseCumulus}/display/message`;
    const body = { username: identity.username, role: identity.role, patientId: identity.patientId };

    const resp = await carelinkPostJson(url, body);
    const recent = resp.data || {};

    // Debug (gekürzt)
    try { setS(DP.status.lastJson, JSON.stringify(recent).slice(0, 1500)); } catch (e) {}

    // 1) JSON schreiben (gefiltert + nur bei Änderung)
    const setCount = writeJsonToStatesFiltered(`${BASE}.data`, recent);
    setS(DP.status.writes, setCount);

    // 2) Komfort: Glukose/Trend/Valid (wie vorher, lastSG + letztes bleibt stehen)
    const g = extractGlucose(recent);
    const prevMgdl = Number(s(DP.internal.prevMgdl) || 0);
    const prevTs = String(s(DP.internal.prevTs) || "");

    if (typeof g.mgdl === "number" && g.mgdl > 0 && g.ts && g.ts !== prevTs) {
      setS(DP.data.mgdl, g.mgdl);
      if (g.mmol != null) setS(DP.data.mmol, g.mmol);
      setS(DP.data.ts, g.ts);

      const delta = Number(g.mgdl - prevMgdl);
      setS(DP.data.delta, delta);
      setS(DP.data.trend, trendFromDelta(delta));

      setS(DP.internal.prevMgdl, g.mgdl);
      setS(DP.internal.prevTs, g.ts);

      setS(DP.data.lastValidUpdate, new Date().toISOString());
    }

    setS(DP.internal.lastPollOk, true);
    setS(DP.status.ok, new Date().toISOString());
    setS(DP.status.code, 200);

    updateValidFromCurrentState();

  } catch (e) {
    const code = e?.response?.status ? Number(e.response.status) : 0;
    const url = e?.config?.url ? String(e.config.url) : "";
    let body = "";

    try {
      if (e?.response?.data !== undefined) {
        body = (typeof e.response.data === "string") ? e.response.data : JSON.stringify(e.response.data);
      }
    } catch (_) {}

    body = String(body || "").slice(0, 800);

    setS(DP.status.code, code);
    setS(DP.status.lastUrl, url);
    setS(DP.status.lastBody, body);
    setS(DP.status.err, (e?.message ? String(e.message) : String(e)));

    // API-Fehler => valid false
    setS(DP.internal.lastPollOk, false);
    updateValidFromCurrentState();

    log(`[CareLink] Fehler: HTTP ${code || "?"} – ${url} – ${e?.message || e}`, "warn");
    if (body) log(`[CareLink] Response body: ${body}`, "warn");

    // 401: Refresh + Retry einmal
    if (code === 401) {
      try {
        await refreshTokenAuth0();
        await pollOnce();
      } catch (e2) {
        const msg2 = e2?.message ? String(e2.message) : String(e2);
        setS(DP.status.err, `401 + refresh retry failed: ${msg2}`);
        setS(DP.internal.lastPollOk, false);
        updateValidFromCurrentState();
      }
    }
  }
}

// =====================
// Start
// =====================
(async () => {
  initStates();
  log("[CareLink] Filtered JSON (changes only) Poller gestartet.", "info");

  await pollOnce();

  setInterval(() => {
    pollOnce().catch((err) => {
      setS(DP.internal.lastPollOk, false);
      updateValidFromCurrentState();
      log(`[CareLink] pollOnce unhandled: ${err}`, "error");
    });
  }, Math.max(20, CFG.pollSeconds) * 1000);

  // Valid regelmäßig neu berechnen
  setInterval(() => updateValidFromCurrentState(), 30 * 1000);
})();
