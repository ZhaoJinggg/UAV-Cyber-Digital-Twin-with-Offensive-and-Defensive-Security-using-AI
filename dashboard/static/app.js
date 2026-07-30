import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';

// ---------------------------------------------------------------- helpers
const $ = (id) => document.getElementById(id);
const PALETTE = ['#4ea1ff', '#38d39f', '#ffb454', '#ff4d5e', '#b980ff',
                 '#f77fbe', '#5fd0e0', '#ffd24d', '#8fce5a', '#ff8a5c'];
let PROFILE = 'mission';
let RUNNING = false;
let SCENARIOS = [];
let CORE_IDS = [];
let attackActive = false;
let idsAlert = false;
let IDS_READY = false;
let SIM = 'unknown';
let PIPELINE = false;
let activeRunKey = null;   // "scenario|run_XX" being recorded right now

// ---------------------------------------------------------------- websocket
let ws;
function connect() {
  ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => setConn(true);
  ws.onclose = () => { setConn(false); setTimeout(connect, 1500); };
  ws.onmessage = (e) => handle(JSON.parse(e.data));
  // keepalive
  setInterval(() => { if (ws.readyState === 1) ws.send('ping'); }, 15000);
}
function setConn(up) {
  const p = $('connPill');
  p.textContent = up ? 'live' : 'disconnected';
  p.className = 'conn ' + (up ? 'up' : 'down');
}

function handle(m) {
  if (m.type === 'log') return addLog(m);
  if (m.type === 'phys') return onPhys(m.data);
  if (m.type === 'net') return onNet(m.data);
  if (m.type === 'ids') return onIds(m.data);
  if (m.type === 'ids_metrics') return onIdsMetrics(m.data);
  if (m.type === 'state') return onState(m.data);
  if (m.type === 'sim') return onSim(m.status);
  if (m.type === 'pt') return onPt(m.data);
  if (m.type === 'run_end') return onRunEnd(m);
  if (m.type === 'hello') {
    RUNNING = m.status === 'running';
    PIPELINE = m.mode === 'pipeline';
    if (m.sim) onSim(m.sim);
    if (m.ids) setIdsStatus(m.ids);
    if (m.pt) onPt(m.pt);
    updateRunButtons();
  }
}

let lastPtOk = false;
let lastPtPose = null;

function onPt(pt) {
  const pill = $('ptPill');
  if (!pill || !pt) return;
  const ok = !!pt.ok;
  const gui = !!pt.gui;
  const flying = !!pt.flying;
  lastPtOk = ok;
  lastPtPose = pt.pose || null;
  pill.className = 'pt-pill ' + (ok ? 'on' : (pt.gzserver > 0 ? 'partial' : 'off'));
  if (ok && flying) pill.textContent = 'PT flying';
  else if (ok) pill.textContent = 'PT live';
  else if (pt.gzserver > 0 && !gui) pill.textContent = 'PT no GUI';
  else if (pt.px4 > 0) pill.textContent = 'PT headless';
  else pill.textContent = 'PT off';
  const pose = pt.pose ? ` iris≈(${Number(pt.pose.x).toFixed(1)},${Number(pt.pose.y).toFixed(1)},z=${Number(pt.pose.z).toFixed(1)})` : '';
  pill.title = (pt.where || 'Physical Twin on UAV display') +
    ` — px4=${pt.px4||0} gzserver=${pt.gzserver||0} gzclient=${pt.gzclient||0}${pose}`;
  updatePtLinkHud();
}

// ---------------------------------------------------------------- simulator
function onSim(status) {
  SIM = status;
  const box = document.querySelector('.sim-status');
  const pill = $('simPill');
  const btn = $('simBtn');
  box.className = 'sim-status ' + status;
  const labels = {
    offline: 'simulator idle', booting: 'simulator booting…',
    ready: 'simulator ready', airborne: 'vehicle airborne',
    busy: 'recording…', stopping: 'stopping…', unknown: 'simulator …'
  };
  pill.textContent = labels[status] || status;
  // sim control button
  if (status === 'offline') { btn.textContent = 'Start sim'; btn.disabled = false; }
  else if (status === 'booting' || status === 'stopping') { btn.textContent = '…'; btn.disabled = true; }
  else if (status === 'busy') { btn.textContent = 'in use'; btn.disabled = true; }
  else { btn.textContent = 'Shutdown'; btn.disabled = false; }
  updateTwinOverlay();
}

let ranOnce = false;
function updateTwinOverlay() {
  const ov = $('twinOverlay'), msg = $('twinOverlayMsg');
  if (RUNNING) { ov.classList.add('hidden'); return; }
  if (SIM === 'booting') {
    msg.innerHTML = 'warming Gazebo + PX4…<br><small>then arm/takeoff is near-instant from home (0, 0)</small>';
    ov.querySelector('.spinner').style.display = '';
    ov.classList.remove('hidden');
  } else if (SIM === 'ready' || SIM === 'airborne') {
    msg.innerHTML = '✔ UAV powered on &amp; ready at home<br><small>click a scenario — arm/takeoff starts immediately</small>';
    ov.querySelector('.spinner').style.display = 'none';
    ov.classList.remove('hidden');
  } else {
    msg.innerHTML = ranOnce
      ? '✔ mission complete — simulator stays warm<br><small>next scenario resets to home (0, 0) then arms quickly</small>'
      : 'UAV standby<br><small>simulator pre-warms in the background for faster arm/takeoff</small>';
    ov.querySelector('.spinner').style.display = 'none';
    ov.classList.remove('hidden');
  }
}

$('simBtn').addEventListener('click', async () => {
  if (SIM === 'offline') {
    await fetch('/api/sim', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'start' }) });
  } else if (SIM === 'ready' || SIM === 'airborne') {
    if (!confirm('Shut down the PX4 simulator on the UAV?')) return;
    await fetch('/api/sim', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'stop' }) });
  }
});

// ---------------------------------------------------------------- scenarios
let RUN_DURATION = 45;
let ATTACK_RUN_DURATION = 36;
let PRE_S = 12, POST_S = 12;
let MISSION_PLAN = [];
let ATTACK_WP = 2;
let currentWp = null;

async function loadScenarios() {
  const r = await fetch('/api/scenarios');
  const d = await r.json();
  SCENARIOS = d.scenarios;
  CORE_IDS = d.core_ids || [];
  if (d.pipeline_scope_default) pipeScope = d.pipeline_scope_default;
  RUN_DURATION = d.run_duration_s || 45;
  ATTACK_RUN_DURATION = d.attack_run_duration_s
    || ((d.pre_attack_s || 12) + (d.attack_dur_s || 12) + (d.post_attack_s || 12));
  PRE_S = d.pre_attack_s || 12; POST_S = d.post_attack_s || PRE_S;
  MISSION_PLAN = d.mission_plan || [];
  ATTACK_WP = d.attack_after_wp ?? 2;
  $('uavHost').textContent = d.uav_host;
  drawMissionRoute();
  PROFILE = d.profile;
  syncProfileSeg();
  const list = $('scenarioList');
  list.innerHTML = '';
  let lastTier = null;
  for (const s of SCENARIOS) {
    if (s.tier !== lastTier) {
      lastTier = s.tier;
      const h = document.createElement('div');
      h.className = 'scen-tier';
      h.textContent = s.tier === 'A'
        ? 'Tier A — IEEE TIFS core matrix'
        : 'Tier B — appendix / multiclass support';
      list.appendChild(h);
    }
    const eff = s.effects || {};
    const pnt = ['P', 'N', 'T'].map(k =>
      `<span class="pnt ${eff[k] ? 'on' : 'off'}" title="${k}">${k}</span>`).join('');
    const el = document.createElement('div');
    el.className = 'scen ' + (s.is_attack ? 'attack' : 'benign') +
      (s.tier === 'B' ? ' tier-b' : ' tier-a');
    el.innerHTML = `
      <div class="row">
        <div>
          <div class="name"><span class="tier-badge">${s.tier || 'A'}</span> ${s.title}</div>
          <div class="cat">${s.category}${s.needs_airborne ? ' · <span class="air">mid-flight</span>' : ''}
            <span class="pnt-row">${pnt}</span></div>
        </div>
        <button class="run" data-id="${s.id}">Run</button>
      </div>
      <div class="desc">${s.desc}</div>
      ${s.hypothesis ? `<div class="hyp">${s.hypothesis}</div>` : ''}
      ${s.defense && s.defense !== 'N/A (baseline)' ? `<div class="def">→ defense: ${s.defense}</div>` : ''}`;
    list.appendChild(el);
  }
  list.querySelectorAll('.run').forEach(b =>
    b.addEventListener('click', () => startRun(b.dataset.id)));
}

async function startRun(id) {
  if (RUNNING) return;
  const body = {
    scenario: id, profile: PROFILE,
    network: $('netToggle').checked
  };
  const r = await fetch('/api/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const d = await r.json();
  if (!d.ok) {
    addLog({ tag: 'dashboard', msg: d.message, ts: Date.now() / 1000 });
    if (isCaptureError(d.message)) openCaptureSetup(() => startRun(id));
    else {
      const b = $('attackBanner');
      if (b) {
        b.className = 'attack-banner banner-attack';
        b.innerHTML = `⚠ CANNOT START<br><b>${escapeHtml(d.message || 'PT offline')}</b>`;
        b.classList.remove('hidden');
      }
    }
    return;
  }
  RUNNING = true; PIPELINE = false; updateRunButtons(); resetLive();
}

$('stopBtn').addEventListener('click', async () => {
  $('stopBtn').disabled = true;
  addLog({ tag: 'dashboard', msg: 'stop requested — aborting…', ts: Date.now() / 1000 });
  const pill = $('phasePill');
  if (pill) { pill.textContent = 'stopping…'; pill.className = 'phase'; }
  try {
    await fetch('/api/stop', { method: 'POST' });
  } catch (e) {
    addLog({ tag: 'dashboard', msg: 'stop request failed: ' + e, ts: Date.now() / 1000 });
  }
});

function updateRunButtons() {
  document.querySelectorAll('.scen .run').forEach(b => b.disabled = RUNNING);
  $('stopBtn').disabled = !RUNNING;
  $('pipelineBtn').disabled = RUNNING;
  if ($('tourBtn')) $('tourBtn').disabled = RUNNING;
}

function onRunEnd() {
  RUNNING = false; PIPELINE = false;
  ranOnce = true;
  const finished = activeRunKey;   // capture before reset
  updateRunButtons();
  resetTwinIdle();
  const pill = $('phasePill');
  pill.textContent = 'ready'; pill.className = 'phase ready';
  updateTwinOverlay();
  hidePipeProgress();
  // one final dataset refresh so the just-saved run is fully shown, then stop
  finalizeDsPolling();
  loadRuns(false).then(() => {
    const sel = $('dsRun');
    if (finished && [...sel.options].some(o => o.value === finished)) {
      sel.value = finished; dsSig = ''; loadDataset();
    }
  });
}

// Bring the twin to a calm idle state once a run/task completes.
// Prefer settling at the last flown pose (already near home after land+reset)
// rather than a hard teleport — the land follow-through already animated down.
function resetTwinIdle() {
  armedNow = 0;
  attackActive = false;
  idsAlert = false;
  twinTracking = false;
  $('attackBanner').classList.add('hidden');
  if ($('idsBanner')) $('idsBanner').classList.add('hidden');
  if ($('defenseBanner')) $('defenseBanner').classList.add('hidden');
  $('scenarioNow').textContent = 'ready';
  setIdsHudClear();
  // Ease toward pad from last pose (no hard teleport)
  target.set(drone.position.x * 0.15, 0.12, drone.position.z * 0.15);
  activeRunKey = null;
}

// ---------------------------------------------------------------- toggles
$('profileSeg').addEventListener('click', (e) => {
  const b = e.target.closest('button'); if (!b) return;
  PROFILE = b.dataset.profile; syncProfileSeg();
});
function syncProfileSeg() {
  $('profileSeg').querySelectorAll('button').forEach(b =>
    b.classList.toggle('on', b.dataset.profile === PROFILE));
}

// ---------------------------------------------------------------- log
function addLog(m) {
  const box = $('logBox');
  const t = new Date((m.ts || Date.now() / 1000) * 1000).toLocaleTimeString();
  const div = document.createElement('div');
  div.className = 'l';
  div.innerHTML = `<span class="t">${t}</span> <span class="tag ${m.tag}">[${m.tag}]</span> ${escapeHtml(m.msg)}`;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
  while (box.children.length > 400) box.removeChild(box.firstChild);
}
$('clearLog').addEventListener('click', () => $('logBox').innerHTML = '');
function escapeHtml(s) { return String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }

// ---------------------------------------------------------------- IDS
function setIdsStatus(st) {
  IDS_READY = !!(st && st.ready);
  const unprotected = !!(st && (st.unprotected || !st.ready));
  const pill = $('idsPill');
  if (pill) {
    if (unprotected) {
      pill.className = 'ids-pill offline';
      pill.textContent = 'IDS · unprotected';
      pill.title = (st && (st.message || st.load_error))
        || 'No trained model — attacks run without detection/defence';
    } else if (!st || !st.ready) {
      pill.className = 'ids-pill offline';
      pill.textContent = 'IDS offline';
      pill.title = (st && st.load_error) || 'train with: python -m ids cnn';
    } else {
      pill.className = 'ids-pill ready';
      pill.textContent = st.enabled === false ? 'IDS off' : ('IDS · ' + (st.modalities || []).join('+'));
      pill.title = 'Trained IDS ready';
    }
  }
  if ($('idsToggle')) $('idsToggle').checked = st.enabled !== false;
  if ($('defenseToggle')) {
    $('defenseToggle').disabled = unprotected;
    if (unprotected) $('defenseToggle').checked = false;
  }
  setDefenseStatus(st);
  // Seed the metrics panel on boot / hello / toggle — otherwise Proactive /
  // Reactive / Block latency stay at the HTML placeholder "—" until the next
  // ids_metrics websocket frame (easy to miss if the page was hard-refreshed
  // mid-idle or the browser cached an older app.js).
  if (st && st.metrics) onIdsMetrics(st.metrics);
  const cnn = st && st.cnn;
  if ($('mCnn')) {
    if (cnn && cnn.ready) {
      const h = cnn.meta || {};
      const f1 = (h.f1_attack != null) ? Number(h.f1_attack).toFixed(2) : '—';
      const prim = (st.primary_model === 'cnn1d' || cnn.primary) ? 'PRIMARY · ' : '';
      $('mCnn').textContent = `${prim}online · F1 ${f1}`;
      $('mCnn').style.color = '#9ef0c8';
    } else if (unprotected) {
      $('mCnn').textContent = 'no model · unprotected';
      $('mCnn').style.color = '#f0c49e';
    } else {
      $('mCnn').textContent = cnn && cnn.error ? 'offline' : '—';
      $('mCnn').style.color = '';
    }
  }
  if (pill && st && st.primary_model === 'cnn1d' && st.ready) {
    pill.textContent = st.enabled === false ? 'IDS off' : 'IDS · TinyMAV 1D-CNN';
    pill.title = 'Primary lightweight IDS: Tiny MAVLink 1D-CNN (+ rules)';
  }
  if ($('hudIds') && unprotected) {
    $('hudIds').textContent = 'unprotected';
    $('hudIds').style.color = '#f0c49e';
  }
  // Only sync Live train from API when the field is present — otherwise a
  // stale / partial status payload would immediately uncheck the box.
  if (st && Object.prototype.hasOwnProperty.call(st, 'live_train')) {
    const lt = st.live_train || {};
    const on = !!(lt.live_train);
    if ($('liveTrainToggle')) $('liveTrainToggle').checked = on;
    if ($('mTrain')) {
      if (lt.training) $('mTrain').textContent = 'training…';
      else if (on) $('mTrain').textContent = 'armed';
      else $('mTrain').textContent = 'off';
    }
  }
}

function setDefenseStatus(st) {
  const unprotected = !!(st && (st.unprotected || st.model_available === false));
  const on = !!(st && st.defense_enabled) && !unprotected;
  const active = !!(st && st.defense_active);
  // Never invent "hybrid" — that made the dropdown flip mid-run when a
  // partial WS payload omitted defense_mode.
  const mode = (st && st.defense_mode)
    || (st && st.gateway && st.gateway.mode)
    || null;
  if ($('defenseToggle')) {
    $('defenseToggle').disabled = unprotected;
    $('defenseToggle').checked = on;
  }
  if ($('defenseMode') && mode) {
    const sel = $('defenseMode');
    if ([...sel.options].some(o => o.value === mode)) sel.value = mode;
  }
  const shown = mode || (($('defenseMode') && $('defenseMode').value) || 'proactive');
  const pill = $('defPill');
  if (pill) {
    if (unprotected) { pill.className = 'def-pill off'; pill.textContent = 'UNPROTECTED'; }
    else if (active) { pill.className = 'def-pill active'; pill.textContent = 'DEFEND'; }
    else if (on) { pill.className = 'def-pill on'; pill.textContent = 'DEF ' + String(shown).slice(0, 3); }
    else { pill.className = 'def-pill off'; pill.textContent = 'DEF off'; }
  }
  if ($('hudDefense')) {
    if (unprotected) {
      $('hudDefense').textContent = 'unprotected';
      $('hudDefense').style.color = '#f0c49e';
    } else {
      $('hudDefense').textContent = active ? ('ACTIVE·' + shown) : (on ? shown : 'off');
      $('hudDefense').style.color = active ? '#38d39f' : (on ? '#9fe7c8' : '');
    }
  }
}

function setIdsHudClear() {
  if ($('hudIds')) { $('hudIds').textContent = IDS_READY ? 'benign' : '—'; $('hudIds').style.color = ''; }
  if ($('hudIdsAction')) $('hudIdsAction').textContent = '—';
  const pill = $('idsPill');
  if (pill && IDS_READY) { pill.className = 'ids-pill ready'; }
  if ($('defenseBanner')) $('defenseBanner').classList.add('hidden');
}

function onIds(d) {
  if (!d) return;
  if (d.event === 'defense_mode') {
    setDefenseStatus({
      defense_enabled: !!d.defense_enabled,
      defense_active: false,
      defense_mode: d.defense_mode || undefined,
      unprotected: !!d.unprotected,
      model_available: d.model_available,
    });
    addLog({ tag: 'defense', msg: d.message || (d.defense_enabled ? 'Defense ON' : 'Defense OFF'), ts: Date.now() / 1000 });
    return;
  }
  if (d.event === 'proactive_block') {
    const b = $('defenseBanner');
    if (b) {
      b.className = 'defense-banner';
      b.innerHTML =
        `🛡 PROACTIVE BLOCK<br><b>${escapeHtml(d.attack_class || 'attack')}</b>` +
        `<div class="ids-meta">pre-PX4 drop · msgid ${d.msgid ?? '—'}` +
        (d.latency_ms != null ? ` · ${Number(d.latency_ms).toFixed(2)} ms` : '') +
        (d.reason ? ` · ${escapeHtml(d.reason)}` : '') +
        `</div>`;
      b.classList.remove('hidden');
    }
    return;
  }
  if (d.event === 'defend') {
    setDefenseStatus({
      defense_enabled: true, defense_active: true, defense_mode: d.defense_mode,
    });
    const b = $('defenseBanner');
    if (b) {
      b.className = 'defense-banner';
      const path = d.defense_path || d.defense_mode || 'defense';
      b.innerHTML =
        `🛡 DEFENSE (${escapeHtml(path)})<br><b>${escapeHtml(d.attack_class || 'attack')}</b>` +
        `<div class="ids-meta">action: <b>${escapeHtml(d.action || '—')}</b>` +
        (d.attack_score != null ? ` · score ${Number(d.attack_score).toFixed(3)}` : '') +
        (d.prevent_hold_s != null ? ` · hold ${Number(d.prevent_hold_s).toFixed(0)}s` : '') +
        (d.engage_reason ? ` · ${escapeHtml(d.engage_reason)}` : '') +
        `</div>`;
      b.classList.remove('hidden');
    }
    addLog({ tag: 'defense', msg: d.message || 'engaging defense', ts: Date.now() / 1000 });
    return;
  }
  if (d.event === 'defend_done') {
    setDefenseStatus({ defense_enabled: d.defense_enabled !== false, defense_active: false });
    if ($('defenseBanner')) $('defenseBanner').classList.add('hidden');
    addLog({ tag: 'defense', msg: d.message || 'defense complete', ts: Date.now() / 1000 });
    return;
  }
  if (d.event === 'reset' || d.event === 'idle') {
    idsAlert = false;
    if ($('idsBanner')) $('idsBanner').classList.add('hidden');
    if ($('defenseBanner')) $('defenseBanner').classList.add('hidden');
    setIdsHudClear();
    if (d.defense_mode) {
      setDefenseStatus({
        defense_enabled: true,
        defense_active: false,
        defense_mode: d.defense_mode,
        unprotected: !!d.unprotected,
      });
    }
    if (d.event === 'reset') addLog({ tag: 'ids', msg: d.message || 'IDS armed', ts: Date.now() / 1000 });
    return;
  }
  const t = (d.t_rel != null) ? d.t_rel : 0;
  if (charts.ids && d.attack_score != null) {
    push(charts.ids, 0, t, d.attack_score);
    // threshold reference line as second series constant
    push(charts.ids, 1, t, 0.5);
    charts.ids.update('none');
  }
  const score = (d.attack_score != null) ? d.attack_score : 0;
  const pred = !!d.attack_pred;
  if ($('hudIds')) {
    $('hudIds').textContent = pred
      ? ((d.attack_class || 'attack') + ' · ' + score.toFixed(2))
      : ('clear · ' + score.toFixed(2));
    $('hudIds').style.color = pred ? '#ff4d5e' : '#38d39f';
  }
  if ($('hudIdsAction')) {
    $('hudIdsAction').textContent = pred ? (d.action || '—') : 'none';
    $('hudIdsAction').style.color = pred ? '#ffb454' : '';
  }
  if (d.cnn1d && $('mCnnScore')) {
    const c = d.cnn1d;
    if (c.ready) {
      $('mCnnScore').textContent =
        (Number(c.attack_score || 0).toFixed(2)) +
        (c.attack_pred ? ` · ${c.attack_class || 'atk'}` : ' · clear');
      $('mCnnScore').style.color = c.attack_pred ? '#ffb454' : '#9ef0c8';
    }
  }
  if (pred && d.ui_alert !== false) {
    idsAlert = true;
    const b = $('idsBanner');
    if (b) {
      b.className = 'ids-banner alert';
      b.innerHTML =
        `🛡 IDS ALERT<br><b>${escapeHtml(d.attack_class || 'attack')}</b>` +
        `<div class="ids-meta">score ${score.toFixed(3)} · ${escapeHtml(d.modality || '')}` +
        (d.class_confidence != null ? ` · conf ${Number(d.class_confidence).toFixed(2)}` : '') +
        `<br>action: <b>${escapeHtml(d.action || '—')}</b>` +
        (d.defense_engaged ? ' · <b>DEFENDING</b>' : (d.defense_enabled ? ' · defense armed' : ' · detect only')) +
        (d.latency_ms != null ? ` · ${Number(d.latency_ms).toFixed(2)} ms` : '') +
        `</div>`;
    }
    const pill = $('idsPill');
    if (pill) { pill.className = 'ids-pill alert'; pill.textContent = 'IDS ALERT'; }
    addLog({
      tag: 'ids',
      msg: `ALERT ${d.attack_class || 'attack'} score=${score.toFixed(3)} → ${d.action || '—'}` +
           (d.defense_engaged ? ' [DEFENSE ENGAGED]' : ' [detect only]'),
      ts: Date.now() / 1000
    });
  } else if (!pred) {
    idsAlert = false;
    if ($('idsBanner')) $('idsBanner').classList.add('hidden');
    const pill = $('idsPill');
    if (pill && IDS_READY) {
      pill.className = 'ids-pill ready';
      pill.textContent = 'IDS clear';
    }
  }
}

if ($('idsToggle')) {
  $('idsToggle').addEventListener('change', async () => {
    const enabled = $('idsToggle').checked;
    try {
      const r = await fetch('/api/ids', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      const st = await r.json();
      setIdsStatus(st);
    } catch (e) {
      addLog({ tag: 'ids', msg: 'failed to toggle IDS: ' + e, ts: Date.now() / 1000 });
    }
  });
}

if ($('defenseToggle')) {
  $('defenseToggle').addEventListener('change', async () => {
    const defense_enabled = $('defenseToggle').checked;
    try {
      const r = await fetch('/api/ids', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ defense_enabled })
      });
      const st = await r.json();
      setIdsStatus(st);
    } catch (e) {
      addLog({ tag: 'defense', msg: 'failed to toggle Defense: ' + e, ts: Date.now() / 1000 });
    }
  });
}
if ($('defenseMode')) {
  $('defenseMode').addEventListener('change', async () => {
    const defense_mode = $('defenseMode').value;
    try {
      const r = await fetch('/api/ids', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ defense_mode })
      });
      const st = await r.json();
      setIdsStatus(st);
      addLog({
        tag: 'defense',
        msg: `Defense mode → ${defense_mode} (proactive=pre-PX4 drop, reactive=reclaim)`,
        ts: Date.now() / 1000
      });
    } catch (e) {
      addLog({ tag: 'defense', msg: 'failed to set defense mode: ' + e, ts: Date.now() / 1000 });
    }
  });
}

if ($('liveTrainToggle')) {
  $('liveTrainToggle').addEventListener('change', async () => {
    const live_train = $('liveTrainToggle').checked;
    $('liveTrainToggle').disabled = true;
    try {
      const r = await fetch('/api/ids', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ live_train })
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const st = await r.json();
      if ($('liveTrainToggle')) $('liveTrainToggle').checked = live_train;
      if (st && Object.prototype.hasOwnProperty.call(st, 'live_train')) setIdsStatus(st);
      else if ($('mTrain')) $('mTrain').textContent = live_train ? 'armed' : 'off';
      addLog({
        tag: 'train',
        msg: live_train
          ? 'Live train ON — after each SITL run models fine-tune on new data, save, and reload'
          : 'Live train OFF',
        ts: Date.now() / 1000
      });
    } catch (e) {
      if ($('liveTrainToggle')) $('liveTrainToggle').checked = !live_train;
      if ($('mTrain')) $('mTrain').textContent = !live_train ? 'armed' : 'off';
      addLog({ tag: 'train', msg: 'failed to toggle Live train: ' + e, ts: Date.now() / 1000 });
    } finally {
      if ($('liveTrainToggle')) $('liveTrainToggle').disabled = false;
    }
  });
}

// ---------------------------------------------------------------- state
function onState(d) {
  const pill = $('phasePill');
  const phase = d.phase || 'idle';
  pill.textContent = (d.phase || 'idle').replace(/_/g, ' ');
  pill.className = 'phase ' + phase;

  // simulator lifecycle reflected in the twin overlay
  if (phase === 'sitl_starting') { SIM = 'booting'; updateTwinOverlay(); }
  if (phase === 'sitl_ready' || phase === 'recording') { SIM = 'busy'; updateTwinOverlay(); }

  if (phase === 'attack') {
    attackActive = true;
    const b = $('attackBanner');
    b.className = 'attack-banner banner-attack';
    b.innerHTML = `⚠ ATTACK ACTIVE<br><b>${d.title || d.scenario}</b><br><span style="color:#ffd7db">${d.effect || ''}</span>`;
  }
  if (phase === 'cooldown' || phase === 'done') {
    attackActive = false; $('attackBanner').classList.add('hidden');
  }
  if (phase === 'error') {
    attackActive = false;
    const b = $('attackBanner');
    if (b) {
      b.className = 'attack-banner banner-attack';
      b.innerHTML = `⚠ RUN FAILED<br><b>${escapeHtml(d.message || 'SITL / PT not ready')}</b>` +
        `<br><span>Check UAV PC reachability, then click Start sim</span>`;
      b.classList.remove('hidden');
    }
    addLog({ tag: 'orch', msg: d.message || 'run failed — SITL/PT not ready',
             ts: Date.now() / 1000 });
  }
  if (phase === 'pre_attack') {
    attackActive = false;
    const b = $('attackBanner');
    b.className = 'attack-banner banner-normal';
    b.innerHTML = '● NORMAL PLAN<br><b>pre-attack — shared mission</b><br><span>flying the normal plan (benign label)</span>';
  }
  if (phase === 'mission_wp') {
    currentWp = d;
    if (d.wp_id) $('scenarioNow').textContent =
      `${d.hint || '→'} ${d.wp_id}` + (attackActive ? '  ⚠ attack' : '  · normal plan');
  }
  if (phase === 'post_attack') {
    attackActive = false;
    const b = $('attackBanner');
    b.className = 'attack-banner banner-normal';
    b.innerHTML = '● NORMAL PLAN<br><b>post-attack — resume mission</b><br><span>same normal plan (benign label)</span>';
    $('scenarioNow').textContent = '● normal plan (post)…';
  }
  if (phase === 'landing' || phase === 'landed' || phase === 'settling') {
    twinTracking = true;
    attackActive = false;
    const b = $('attackBanner');
    b.className = 'attack-banner banner-land';
    if (phase === 'landing') {
      b.innerHTML = '⤵ LANDING<br><b>DT tracking PT descent</b><br><span>smooth follow-through</span>';
    } else if (phase === 'landed') {
      b.innerHTML = '● LANDED<br><b>on pad</b><br><span>settling before home reset</span>';
    } else {
      b.innerHTML = '● SETTLING<br><b>soft home reset</b><br><span>avoiding DT snap</span>';
    }
  }
  if (phase === 'home_reset') {
    twinTracking = true;
    // gently aim at home; clamp in updateTwin will ease the Gazebo teleport
    target.set(0, 0.12, 0);
  }
  if (phase === 'sitl_ready' && !RUNNING) {
    $('attackBanner').classList.add('hidden');
    twinTracking = false;
  }
  if (phase === 'recording') {
    twinTracking = true;
    resetLive();
    if (d.scenario) $('scenarioNow').textContent =
      (d.is_attack ? '⚠ ' : '● ') + d.scenario + (d.run_name ? ' / ' + d.run_name : '');
    if (d.attack_schedule) {
      ATTACK_GATES = new Set((d.attack_schedule || []).map(e => e.after_wp));
      drawMissionRoute();
      addLog({ tag: 'dashboard', msg: 'attack schedule: ' +
        (d.attack_schedule || []).map(e => `${e.wp_id}→${e.attack}`).join(', '),
        ts: Date.now() / 1000 });
    }
    // begin live-plotting the run that is being recorded, straight from disk
    if (d.scenario && d.run_name) beginLiveDataset(d.scenario, d.run_name);
  }

  // ------- pipeline progress -------
  if (phase.startsWith('pipeline')) PIPELINE = true;
  if (phase === 'pipeline_start') {
    showPipeProgress(); setPipe(0, d.total || 0, 'starting…');
  } else if (phase === 'pipeline_progress') {
    setPipe(d.done || 0, d.total || 0,
      `${d.scenario || ''}${d.run != null ? ' · run ' + d.run : ''}`);
  } else if (phase === 'pipeline_build') {
    setPipe(d.done || 0, d.total || 0, 'preprocessing datasets…');
  } else if (phase === 'pipeline_done') {
    setPipe(d.total || 0, d.total || 0, 'complete ✓');
    if (d.datasets) reportDatasets(d.datasets);
    setTimeout(hidePipeProgress, 4000);
  } else if (phase === 'pipeline_stopped') {
    setPipe(d.done || 0, d.total || 0, 'stopped');
    setTimeout(hidePipeProgress, 2500);
  }
}

// ---------------------------------------------------------------- pipeline UI
function showPipeProgress() { $('pipeProgress').classList.remove('hidden'); }
function hidePipeProgress() { $('pipeProgress').classList.add('hidden'); }
function setPipe(done, total, stage) {
  $('pipeStage').textContent = 'Pipeline — ' + (stage || '');
  $('pipeCount').textContent = `${done} / ${total}`;
  $('pipeFill').style.width = total ? Math.min(100, (done / total) * 100) + '%' : '0%';
}
function reportDatasets(summary) {
  const rows = (summary.files || []).map(f => `${f.name}: ${f.rows} rows × ${f.cols} cols`).join(' | ');
  addLog({ tag: 'dashboard', msg: 'datasets built → ' + rows, ts: Date.now() / 1000 });
  if (summary.class_balance) {
    const cb = Object.entries(summary.class_balance).map(([k, v]) => `${k}=${v}`).join(', ');
    addLog({ tag: 'dashboard', msg: 'class balance (physical_processed): ' + cb, ts: Date.now() / 1000 });
  }
}

// ---------------------------------------------------------------- 3D twin
let scene, camera, renderer, controls, drone, rotors = [], propDiscs = [], trailLine, trailPts = [];
const target = new THREE.Vector3(0, 0, 0);
let bodyMat;

function initTwin() {
  const host = $('twin3d');
  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x0a0f1a);
  scene.fog = new THREE.Fog(0x0a0f1a, 60, 160);

  camera = new THREE.PerspectiveCamera(50, host.clientWidth / host.clientHeight, 0.1, 500);
  camera.position.set(9, 6, 12);

  renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setSize(host.clientWidth, host.clientHeight);
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  host.appendChild(renderer.domElement);

  controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true; controls.target.set(0, 2.5, 0);
  controls.minDistance = 4; controls.maxDistance = 130;
  controls.autoRotate = true; controls.autoRotateSpeed = 0.6;

  scene.add(new THREE.HemisphereLight(0xbcd4ff, 0x101828, 1.0));
  const key = new THREE.DirectionalLight(0xffffff, 1.4);
  key.position.set(24, 48, 18); key.castShadow = true;
  key.shadow.mapSize.set(2048, 2048);
  const s = 60; key.shadow.camera.left = -s; key.shadow.camera.right = s;
  key.shadow.camera.top = s; key.shadow.camera.bottom = -s;
  key.shadow.camera.near = 1; key.shadow.camera.far = 160; key.shadow.bias = -0.0004;
  scene.add(key);
  const rim = new THREE.DirectionalLight(0x4ea1ff, 0.5); rim.position.set(-30, 20, -25); scene.add(rim);

  // ground plane (for soft shadows) + grid overlay
  const ground = new THREE.Mesh(new THREE.PlaneGeometry(400, 400),
    new THREE.MeshStandardMaterial({ color: 0x0c1220, roughness: 1, metalness: 0 }));
  ground.rotation.x = -Math.PI / 2; ground.position.y = -0.01; ground.receiveShadow = true;
  scene.add(ground);
  const grid = new THREE.GridHelper(120, 60, 0x24405f, 0x162334); scene.add(grid);
  const axes = new THREE.AxesHelper(8); scene.add(axes); // X=east(red) Y=up(green) Z=north(blue)

  const home = new THREE.Mesh(new THREE.SphereGeometry(0.45, 20, 20),
    new THREE.MeshStandardMaterial({ color: 0x4ea1ff, emissive: 0x123a66, emissiveIntensity: 1 }));
  scene.add(home);
  // launch-pad ring
  const ring = new THREE.Mesh(new THREE.RingGeometry(1.6, 2.0, 40),
    new THREE.MeshBasicMaterial({ color: 0x4ea1ff, transparent: true, opacity: 0.4, side: THREE.DoubleSide }));
  ring.rotation.x = -Math.PI / 2; ring.position.y = 0.02; scene.add(ring);

  drone = buildIrisDrone(); scene.add(drone);
  tryLoadGLB();  // optional: /static/models/drone.glb overrides the procedural model

  const tgeo = new THREE.BufferGeometry();
  tgeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(300 * 3), 3));
  trailLine = new THREE.Line(tgeo, new THREE.LineBasicMaterial({ color: 0x38d39f, transparent: true, opacity: 0.85 }));
  trailLine.geometry.setDrawRange(0, 0);
  scene.add(trailLine);

  window.addEventListener('resize', onResize);
  animate();
}

// --- Faithful 3DR Iris-style quadcopter (PX4 SITL default airframe) ---------
function buildIrisDrone() {
  const g = new THREE.Group();
  const carbon = new THREE.MeshStandardMaterial({ color: 0x14181f, metalness: .35, roughness: .55 });
  bodyMat = new THREE.MeshStandardMaterial({ color: 0x20262f, metalness: .3, roughness: .5 }); // top shell
  const armFront = new THREE.MeshStandardMaterial({ color: 0xd23b3b, metalness: .2, roughness: .6 });
  const armBack = new THREE.MeshStandardMaterial({ color: 0x2a2f38, metalness: .2, roughness: .6 });
  const motorMat = new THREE.MeshStandardMaterial({ color: 0x0c0e12, metalness: .6, roughness: .4 });
  const bell = new THREE.MeshStandardMaterial({ color: 0xff8a3c, metalness: .5, roughness: .35 });

  // fuselage: lower carbon plate + rounded top shell
  const plate = new THREE.Mesh(new THREE.BoxGeometry(1.7, 0.12, 1.0), carbon);
  plate.castShadow = true; g.add(plate);
  const shell = new THREE.Mesh(new THREE.CapsuleGeometry(0.45, 0.9, 6, 14), bodyMat);
  shell.rotation.z = Math.PI / 2; shell.position.y = 0.22; shell.scale.set(1, 1, 0.7);
  shell.castShadow = true; g.add(shell);
  // GPS mast + puck
  const mast = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 0.7, 8), carbon);
  mast.position.set(-0.45, 0.5, 0); g.add(mast);
  const gps = new THREE.Mesh(new THREE.CylinderGeometry(0.28, 0.28, 0.08, 20), bodyMat);
  gps.position.set(-0.45, 0.85, 0); gps.castShadow = true; g.add(gps);

  const L = 1.35;                 // arm length (X-config)
  const arms = [
    { x: L, z: L, front: true }, { x: L, z: -L, front: true },
    { x: -L, z: L, front: false }, { x: -L, z: -L, front: false },
  ];
  const ccw = [true, false, false, true];
  arms.forEach((a, i) => {
    const len = Math.hypot(a.x, a.z);
    const arm = new THREE.Mesh(new THREE.BoxGeometry(0.16, 0.12, len), a.front ? armFront : armBack);
    arm.position.set(a.x / 2, 0.02, a.z / 2);
    arm.lookAt(new THREE.Vector3(a.x, 0.02, a.z));
    arm.castShadow = true; g.add(arm);

    const motor = new THREE.Mesh(new THREE.CylinderGeometry(0.17, 0.19, 0.26, 18), motorMat);
    motor.position.set(a.x, 0.14, a.z); motor.castShadow = true; g.add(motor);
    const cap = new THREE.Mesh(new THREE.CylinderGeometry(0.15, 0.15, 0.06, 18), bell);
    cap.position.set(a.x, 0.30, a.z); g.add(cap);

    // propeller hub + 2 thin blades (spins)
    const prop = new THREE.Group(); prop.position.set(a.x, 0.36, a.z);
    const hub = new THREE.Mesh(new THREE.CylinderGeometry(0.07, 0.07, 0.05, 10), motorMat);
    prop.add(hub);
    const bladeMat = new THREE.MeshStandardMaterial({
      color: a.front ? 0xe8e8ee : 0x3a4150, metalness: .1, roughness: .7,
      transparent: true, opacity: 0.95, side: THREE.DoubleSide });
    for (let b = 0; b < 2; b++) {
      const blade = new THREE.Mesh(new THREE.BoxGeometry(0.95, 0.02, 0.14), bladeMat);
      blade.position.x = 0; blade.rotation.y = b * Math.PI;
      blade.geometry.translate(0.42, 0, 0);
      blade.castShadow = true; prop.add(blade);
    }
    prop.userData.ccw = ccw[i];
    g.add(prop); rotors.push(prop);
    // spinning translucent disc (visible when armed)
    const disc = new THREE.Mesh(new THREE.CircleGeometry(0.95, 28),
      new THREE.MeshBasicMaterial({ color: 0x8fb4ff, transparent: true, opacity: 0, side: THREE.DoubleSide }));
    disc.rotation.x = -Math.PI / 2; disc.position.set(a.x, 0.37, a.z);
    disc.userData.isDisc = true; g.add(disc); propDiscs.push(disc);
  });

  // landing gear
  const legMat = carbon;
  [[0.7, 0.55], [0.7, -0.55], [-0.7, 0.55], [-0.7, -0.55]].forEach(([x, z]) => {
    const leg = new THREE.Mesh(new THREE.CylinderGeometry(0.045, 0.045, 0.6, 8), legMat);
    leg.position.set(x, -0.32, z); leg.castShadow = true; g.add(leg);
  });
  [[0, 0.6], [0, -0.6]].forEach(([, z]) => {
    const skid = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 1.5, 8), legMat);
    skid.rotation.z = Math.PI / 2; skid.position.set(0, -0.6, z); g.add(skid);
  });

  // nav LEDs: front white/green, rear red
  const led = (x, z, c) => {
    const l = new THREE.Mesh(new THREE.SphereGeometry(0.07, 8, 8),
      new THREE.MeshStandardMaterial({ color: c, emissive: c, emissiveIntensity: 2 }));
    l.position.set(x, 0.12, z); g.add(l);
  };
  led(0.85, 0.0, 0x00ff66); led(-0.85, 0.0, 0xff2a2a);

  g.scale.setScalar(1.7);
  return g;
}

function tryLoadGLB() {
  const url = '/static/models/drone.glb';
  fetch(url, { method: 'HEAD' }).then(r => {
    if (!r.ok) return;                 // no custom model provided
    new GLTFLoader().load(url, (gltf) => {
      const m = gltf.scene;
      // normalise size to ~4 units and drop-in place of procedural model
      const box = new THREE.Box3().setFromObject(m);
      const size = box.getSize(new THREE.Vector3());
      const scale = 4 / Math.max(size.x, size.y, size.z);
      m.scale.setScalar(scale);
      m.traverse(o => { if (o.isMesh) { o.castShadow = true; } });
      scene.remove(drone); rotors = []; propDiscs = [];
      drone = m; scene.add(drone);
      addLog({ tag: 'twin', msg: 'loaded custom drone.glb model', ts: Date.now() / 1000 });
    }, undefined, () => {});
  }).catch(() => {});
}

function onResize() {
  const host = $('twin3d');
  camera.aspect = host.clientWidth / host.clientHeight; camera.updateProjectionMatrix();
  renderer.setSize(host.clientWidth, host.clientHeight);
}

let armedNow = 0, propSpeed = 0;
let twinTracking = false;   // true only while fresh PT phys samples arrive
let lastTwinAlt = 0.12;
let lastTwinPos = { x: 0, y: 0.12, z: 0 };
let lastPhysAt = 0;                 // performance.now() of last PT sample
const PT_STALE_MS = 2500;           // allow brief phys→twin handoff without freeze

function ptLinkLive() {
  return lastPhysAt > 0 && (performance.now() - lastPhysAt) < PT_STALE_MS;
}

function updatePtLinkHud() {
  const el = $('hudPtLink');
  if (!el) return;
  if (ptLinkLive()) {
    const age = ((performance.now() - lastPhysAt) / 1000).toFixed(2);
    el.textContent = `LIVE · ${age}s`;
    el.style.color = '#38d39f';
  } else if (lastPhysAt > 0) {
    el.textContent = RUNNING ? 'STALE — frozen' : 'idle · PT ready';
    el.style.color = RUNNING ? '#ffb454' : '#7ec8ff';
  } else if (lastPtOk) {
    // PT (Gazebo/PX4) is up; DT pose stream only flows during a recorded run.
    el.textContent = 'PT ready · start run to sync';
    el.style.color = '#7ec8ff';
  } else {
    el.textContent = 'no PT data';
    el.style.color = '';
  }
}

function animate() {
  requestAnimationFrame(animate);
  // DT must never look "alive" without a fresh Physical Twin sample.
  const live = ptLinkLive();
  if (!live && twinTracking) twinTracking = false;
  updatePtLinkHud();
  // Hard sync while tracking PT; hold still when PT link is stale/idle
  const k = twinTracking ? 0.55 : 0.08;
  drone.position.x += (target.x - drone.position.x) * k;
  drone.position.y += (target.y - drone.position.y) * k;
  drone.position.z += (target.z - drone.position.z) * k;
  // Props only spin when armed AND we still have a live PT link
  const wanted = (armedNow && live) ? 1.4 : 0.0;
  propSpeed += (wanted - propSpeed) * 0.15;
  for (const r of rotors) r.rotation.y += (r.userData && r.userData.ccw ? 1 : -1) * propSpeed;
  const discOp = Math.min(0.28, propSpeed * 0.2);
  for (const d of propDiscs) if (d.material) d.material.opacity = discOp;
  if (bodyMat) {
    bodyMat.emissive = new THREE.Color((attackActive || idsAlert) ? 0x5a0d14 : 0x0a2e22);
    bodyMat.emissiveIntensity = (attackActive || idsAlert) ? 1.0 : (twinTracking ? 0.25 : 0);
  }
  // Never auto-rotate during a live flight (looks like fake motion).
  // Soft idle spin only when truly idle with no PT link.
  controls.autoRotate = !live && !RUNNING && !twinTracking;
  controls.autoRotateSpeed = 0.35;
  const follow = twinTracking ? drone.position : new THREE.Vector3(0, 2.5, 0);
  controls.target.lerp(follow, twinTracking ? 0.2 : 0.02);
  if (twinTracking) {
    const offset = new THREE.Vector3(9, 6, 12);
    const desired = follow.clone().add(offset);
    camera.position.lerp(desired, 0.1);
  }
  controls.update();
  renderer.render(scene, camera);
}

// NED -> three: X_three=east(y_ned), Y_three=up(-z_ned), Z_three=north(x_ned)
// ONLY called from live WebSocket phys samples (PX4 ← Gazebo PT). Never from CSV.
function updateTwin(d) {
  if (!d || (d.x == null && d.y == null && d.z == null && d.rel_alt == null)) return;
  lastPhysAt = performance.now();
  const north = num(d.x), east = num(d.y);
  // Prefer LOCAL_POSITION z; never treat missing as ground (that caused DT snap)
  let alt;
  if (d.z != null && !isNaN(d.z)) alt = -d.z;
  else if (d.rel_alt != null && !isNaN(d.rel_alt)) alt = Number(d.rel_alt);
  else alt = lastTwinAlt;
  alt = Math.max(alt, 0);
  // Clamp sudden jumps (home teleport / NaN recovery) for smooth DT motion
  const maxStep = twinTracking ? 0.85 : 3.0;
  const dx = east - lastTwinPos.x;
  const dy = alt - lastTwinPos.y;
  const dz = north - lastTwinPos.z;
  const dist = Math.sqrt(dx*dx + dy*dy + dz*dz);
  let nx = east, ny = alt, nz = north;
  if (dist > maxStep && dist > 0.001) {
    const s = maxStep / dist;
    nx = lastTwinPos.x + dx * s;
    ny = lastTwinPos.y + dy * s;
    nz = lastTwinPos.z + dz * s;
  }
  lastTwinPos = { x: nx, y: ny, z: nz };
  lastTwinAlt = ny;
  target.set(nx, ny, nz);
  twinTracking = true;
  drone.rotation.order = 'YXZ';
  if (d.yaw != null && !isNaN(d.yaw)) drone.rotation.y = -num(d.yaw);
  if (d.pitch != null && !isNaN(d.pitch)) drone.rotation.x = num(d.pitch);
  if (d.roll != null && !isNaN(d.roll)) drone.rotation.z = -num(d.roll);
  if (d.armed != null) armedNow = d.armed ? 1 : 0;
  trailPts.push(new THREE.Vector3(nx, ny, nz));
  if (trailPts.length > 400) trailPts.shift();
  const arr = trailLine.geometry.attributes.position.array;
  trailPts.forEach((p, i) => { arr[i * 3] = p.x; arr[i * 3 + 1] = p.y; arr[i * 3 + 2] = p.z; });
  trailLine.geometry.attributes.position.needsUpdate = true;
  trailLine.geometry.setDrawRange(0, trailPts.length);
  updatePtLinkHud();
}
function num(v) { return (v == null || isNaN(v)) ? 0 : v; }

// Planned mission route (shared across all scenarios) — NED x=N, y=E
let missionLine = null, missionMarkers = [];
let ATTACK_GATES = new Set();  // waypoint indices used as attack gates (tour)
function drawMissionRoute() {
  if (!scene || !MISSION_PLAN.length) return;
  if (missionLine) { scene.remove(missionLine); missionLine.geometry.dispose(); }
  missionMarkers.forEach(m => scene.remove(m)); missionMarkers = [];
  const pts = MISSION_PLAN.map(w => new THREE.Vector3(w.y, w.z, w.x));
  const geo = new THREE.BufferGeometry().setFromPoints(pts);
  missionLine = new THREE.Line(geo, new THREE.LineDashedMaterial({
    color: 0x38d39f, dashSize: 1.2, gapSize: 0.6, opacity: 0.55, transparent: true
  }));
  missionLine.computeLineDistances();
  scene.add(missionLine);
  MISSION_PLAN.forEach((w, i) => {
    const isGate = ATTACK_GATES.has(i) || (ATTACK_GATES.size === 0 && i === ATTACK_WP);
    const col = isGate ? 0xff4d5e : 0x4ea1ff;
    const m = new THREE.Mesh(
      new THREE.SphereGeometry(isGate ? 0.55 : 0.4, 12, 12),
      new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.85 })
    );
    m.position.set(w.y, w.z, w.x);
    scene.add(m); missionMarkers.push(m);
  });
}

// 2D top-down map — planned route + live trail
const mapCtx = $('map2d').getContext('2d');
function drawMap() {
  const W = 180, H = 180, R = 45;
  mapCtx.clearRect(0, 0, W, H);
  mapCtx.strokeStyle = '#1f2a3d';
  mapCtx.beginPath(); mapCtx.moveTo(W / 2, 0); mapCtx.lineTo(W / 2, H); mapCtx.moveTo(0, H / 2); mapCtx.lineTo(W, H / 2); mapCtx.stroke();
  const toPx = (east, north) => [W / 2 + (east / R) * (W / 2), H / 2 - (north / R) * (H / 2)];
  // planned route
  if (MISSION_PLAN.length) {
    mapCtx.strokeStyle = 'rgba(56,211,159,0.55)'; mapCtx.setLineDash([4, 3]); mapCtx.beginPath();
    MISSION_PLAN.forEach((w, i) => {
      const [px, py] = toPx(w.y, w.x);
      i ? mapCtx.lineTo(px, py) : mapCtx.moveTo(px, py);
    });
    mapCtx.stroke(); mapCtx.setLineDash([]);
    MISSION_PLAN.forEach((w, i) => {
      const [px, py] = toPx(w.y, w.x);
      const isGate = ATTACK_GATES.has(i);
      mapCtx.fillStyle = isGate ? '#ff4d5e' : '#4ea1ff';
      mapCtx.beginPath(); mapCtx.arc(px, py, isGate ? 4 : 3, 0, 7); mapCtx.fill();
    });
  }
  mapCtx.strokeStyle = (attackActive || idsAlert) ? '#ff4d5e' : '#38d39f'; mapCtx.beginPath();
  trailPts.forEach((p, i) => { const [px, py] = toPx(p.x, p.z); i ? mapCtx.lineTo(px, py) : mapCtx.moveTo(px, py); });
  mapCtx.stroke();
  if (trailPts.length) {
    const last = trailPts[trailPts.length - 1]; const [px, py] = toPx(last.x, last.z);
    mapCtx.fillStyle = (attackActive || idsAlert) ? '#ff4d5e' : '#38d39f';
    mapCtx.beginPath(); mapCtx.arc(px, py, 4, 0, 7); mapCtx.fill();
  }
}

// ---------------------------------------------------------------- live charts
Chart.defaults.color = '#8493ad';
Chart.defaults.borderColor = '#1f2a3d';
Chart.defaults.font.size = 10;

function liveChart(id, names) {
  return new Chart($(id), {
    type: 'line',
    data: { datasets: names.map((n, i) => ({ label: n, data: [], borderColor: PALETTE[i % PALETTE.length], borderWidth: 1.5, pointRadius: 0, tension: .25, spanGaps: true })) },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      scales: { x: { type: 'linear', ticks: { maxTicksLimit: 6 } }, y: { ticks: { maxTicksLimit: 5 } } },
      plugins: { legend: { display: names.length > 1, labels: { boxWidth: 10, padding: 6 } } }
    }
  });
}
let charts = {};
const MAXPTS = 700;
function initCharts() {
  charts.alt = liveChart('cAlt', ['altitude']);
  charts.speed = liveChart('cSpeed', ['speed', 'horiz', 'tilt']);
  charts.raw = liveChart('cRaw', ['raw msgs/s']);
  charts.net = liveChart('cNet', ['pkt/s', 'to uav', 'from uav']);
  charts.ids = liveChart('cIds', ['attack score', 'threshold']);
  charts.metrics = liveChart('cMetrics', ['precision', 'recall', 'f1', 'accuracy']);
  charts.conf = liveChart('cConf', ['TP', 'FP', 'TN', 'FN']);
  charts.delay = liveChart('cDelay', ['det. delay s', 'mean delay']);
  charts.mix = liveChart('cMix', ['command_long', 'heartbeat', 'param_set', 'rc_override', 'gps_input', 'manual_control', 'set_mode', 'mission']);
  // threshold series style
  if (charts.ids.data.datasets[1]) {
    charts.ids.data.datasets[1].borderDash = [4, 4];
    charts.ids.data.datasets[1].borderColor = '#8493ad';
    charts.ids.data.datasets[1].pointRadius = 0;
  }
  if (charts.ids.options && charts.ids.options.scales && charts.ids.options.scales.y) {
    charts.ids.options.scales.y.min = 0;
    charts.ids.options.scales.y.max = 1;
  }
  if (charts.metrics.options && charts.metrics.options.scales && charts.metrics.options.scales.y) {
    charts.metrics.options.scales.y.min = 0;
    charts.metrics.options.scales.y.max = 1;
  }
}

let _metricsT = 0;
function onIdsMetrics(m) {
  if (!m) return;
  _metricsT += 1;
  const t = _metricsT;
  if (charts.metrics) {
    push(charts.metrics, 0, t, m.precision || 0);
    push(charts.metrics, 1, t, m.recall || 0);
    push(charts.metrics, 2, t, m.f1 || 0);
    push(charts.metrics, 3, t, m.accuracy || 0);
    charts.metrics.update('none');
  }
  if (charts.conf) {
    push(charts.conf, 0, t, m.tp || 0);
    push(charts.conf, 1, t, m.fp || 0);
    push(charts.conf, 2, t, m.tn || 0);
    push(charts.conf, 3, t, m.fn || 0);
    charts.conf.update('none');
  }
  if (charts.delay) {
    if (m.last_detection_delay_s != null) push(charts.delay, 0, t, m.last_detection_delay_s);
    if (m.mean_detection_delay_s != null) push(charts.delay, 1, t, m.mean_detection_delay_s);
    charts.delay.update('none');
  }
  const fmt = (v) => (v == null || isNaN(v)) ? '—' : Number(v).toFixed(3);
  if ($('mPrec')) $('mPrec').textContent = fmt(m.precision);
  if ($('mRec')) $('mRec').textContent = fmt(m.recall);
  if ($('mF1')) $('mF1').textContent = fmt(m.f1);
  if ($('mAcc')) $('mAcc').textContent = fmt(m.accuracy);
  if ($('mFpr')) $('mFpr').textContent = fmt(m.fpr);
  if ($('mDelay')) $('mDelay').textContent = m.mean_detection_delay_s != null
    ? (m.mean_detection_delay_s.toFixed(2) + ' s') : '—';
  if ($('mMit')) $('mMit').textContent = m.mean_mitigation_delay_s != null
    ? (m.mean_mitigation_delay_s.toFixed(2) + ' s') : '—';
  if ($('mDefRate')) $('mDefRate').textContent = m.defense_success_rate != null
    ? ((m.defense_success_rate * 100).toFixed(0) + '%') : '—';
  if ($('mResume')) $('mResume').textContent = m.mission_resume_rate != null
    ? ((m.mission_resume_rate * 100).toFixed(0) + `% (${m.mission_resume_ok||0}/${(m.mission_resume_ok||0)+(m.mission_resume_fail||0)})`)
    : '—';
  if ($('mConf')) $('mConf').textContent = `${m.tp||0}/${m.fp||0}/${m.tn||0}/${m.fn||0}`;
  if ($('mAlerts')) $('mAlerts').textContent = `${m.alerts_total != null ? m.alerts_total : (m.detections||0)}`;
  if ($('mScores')) $('mScores').textContent = `${m.n_scores || 0}`;
  if ($('mFp')) $('mFp').textContent = `${m.fp || 0}`;
  if ($('mPro')) $('mPro').textContent = `${m.proactive_blocks||0}` +
    (m.proactive_ok != null ? ` (ok ${m.proactive_ok})` : '');
  if ($('mRea')) $('mRea').textContent = `${m.reactive_recovers||0}` +
    (m.reactive_ok != null ? ` (ok ${m.reactive_ok})` : '');
  if ($('mProLat')) $('mProLat').textContent = m.mean_proactive_block_ms != null
    ? (m.mean_proactive_block_ms.toFixed(2) + ' ms') : '—';
  if ($('mDef')) $('mDef').textContent = `${m.defenses||0}` +
    (m.defense_success != null ? ` (ok ${m.defense_success})` : '');
  renderModelStrength(m);
  renderAttackTable(m);
}

/** Per-attack + overall verdict for the trained detector (no prevention). */
function attackDetectStrength(r) {
  const win = r.gt_windows || 0;
  const caught = r.windows_detected || 0;
  const alerts = r.detections || 0;
  if (win <= 0) {
    if (alerts > 0) {
      return {
        level: 'retrain', label: 'false alarm',
        pct: null,
        guide: 'Model fired on a class not injected — more training / cleaner labels needed',
      };
    }
    return {
      level: 'idle', label: '—', pct: null,
      guide: 'No ground-truth window for this class in the current run',
    };
  }
  const pct = caught / win;
  if (pct >= 0.9 && alerts > 0) {
    return {
      level: 'strong', label: 'strong', pct,
      guide: 'Model reliably catches this attack',
    };
  }
  if (pct >= 0.5) {
    return {
      level: 'ok', label: 'partial', pct,
      guide: 'Detects some windows — more runs / fine-tune recommended',
    };
  }
  if (caught === 0 && alerts === 0) {
    return {
      level: 'weak', label: 'missed', pct,
      guide: 'Attack windows not detected — training needed',
    };
  }
  return {
    level: 'retrain', label: 'weak', pct,
    guide: 'Low catch rate — retrain or collect more of this attack',
  };
}

function overallModelStrength(m, rows) {
  const n = m.n_scores || 0;
  if (n < 20) {
    return {
      level: 'idle', text: 'awaiting run',
      hint: 'Live scores from the trained IDS against ground-truth attack windows. Run a scenario to judge model power.',
    };
  }
  const f1 = Number(m.f1 || 0);
  const rec = Number(m.recall || 0);
  const fpr = Number(m.fpr || 0);
  const trueRows = (rows || []).filter(r => (r.gt_windows || 0) > 0);
  let winCatch = 0, winTotal = 0, missed = 0;
  for (const r of trueRows) {
    winCatch += r.windows_detected || 0;
    winTotal += r.gt_windows || 0;
    missed += Math.max(0, (r.gt_windows || 0) - (r.windows_detected || 0));
  }
  const catchRate = winTotal ? (winCatch / winTotal) : null;
  const falseAlarmRows = (rows || []).filter(r => (r.gt_windows || 0) <= 0 && (r.detections || 0) > 0).length;

  if (f1 >= 0.75 && rec >= 0.7 && fpr <= 0.15 && (catchRate == null || catchRate >= 0.8) && falseAlarmRows === 0) {
    return {
      level: 'strong', text: 'strong model',
      hint: `F1 ${f1.toFixed(2)} · recall ${rec.toFixed(2)} · FPR ${fpr.toFixed(2)} — trained model looks powerful on this run.`,
      winCatch, winTotal, missed, falseAlarmRows,
    };
  }
  if (f1 >= 0.45 && rec >= 0.4 && (catchRate == null || catchRate >= 0.4)) {
    return {
      level: 'ok', text: 'partial · more training',
      hint: `Usable but uneven (F1 ${f1.toFixed(2)}). Fine-tune on weak attack classes below.`,
      winCatch, winTotal, missed, falseAlarmRows,
    };
  }
  return {
    level: 'retrain', text: 'needs training',
    hint: `Weak live detection (F1 ${f1.toFixed(2)}, recall ${rec.toFixed(2)}). Collect more attack runs and retrain.`,
    winCatch, winTotal, missed, falseAlarmRows,
  };
}

function renderModelStrength(m) {
  const rows = m.by_attack || [];
  const overall = overallModelStrength(m, rows);
  const badge = $('modelStrengthBadge');
  if (badge) {
    badge.className = 'strength-badge ' + overall.level;
    badge.textContent = overall.text;
  }
  const hint = $('modelStrengthHint');
  if (hint) hint.textContent = overall.hint;
  if ($('mWinCatch')) {
    const wc = overall.winCatch != null ? overall.winCatch : 0;
    const wt = overall.winTotal != null ? overall.winTotal : 0;
    $('mWinCatch').textContent = wt ? `${wc}/${wt}` : '—';
  }
  if ($('mMiss')) {
    $('mMiss').textContent = overall.missed != null ? `${overall.missed}` : '—';
  }

  const body = $('modelAtkBody');
  if (!body) return;
  const trueOrAlert = rows.filter(r => (r.gt_windows || 0) > 0 || (r.detections || 0) > 0);
  if (!trueOrAlert.length) {
    body.innerHTML = '<tr><td colspan="6" class="atk-empty">Run a scenario to score the trained model</td></tr>';
    return;
  }
  body.innerHTML = trueOrAlert.map(r => {
    const s = attackDetectStrength(r);
    const pctTxt = s.pct == null ? '—' : ((s.pct * 100).toFixed(0) + '%');
    const trCls = (r.gt_windows || 0) > 0 ? 'true-atk' : 'mispred';
    return `<tr class="${trCls}">
      <td>${escapeHtml(r.attack)}</td>
      <td>${r.detections || 0}</td>
      <td>${r.windows_detected || 0}/${r.gt_windows || 0}</td>
      <td class="det-pct">${pctTxt}</td>
      <td class="str-${s.level}">${escapeHtml(s.label)}</td>
      <td class="atk-note">${escapeHtml(s.guide)}</td>
    </tr>`;
  }).join('');
}

function renderAttackTable(m) {
  const body = $('atkTableBody');
  if (!body) return;
  const rows = m.by_attack || [];
  const rowHtml = (name, det, wdet, win, pro, rea, ok, mis, note) => {
    const noteTxt = note || (mis ? 'model misprediction (not injected this run)' : 'true attack window');
    const noteCls = mis ? 'atk-note mis' : 'atk-note true';
    const trCls = mis ? 'mispred' : 'true-atk';
    return `<tr class="${trCls}">
      <td>${escapeHtml(name)}</td>
      <td>${det}</td>
      <td>${wdet}/${win}</td>
      <td class="pro-cell">${pro}</td>
      <td class="rea-cell">${rea}</td>
      <td>${ok}</td>
      <td class="${noteCls}">${escapeHtml(noteTxt)}</td>
    </tr>`;
  };
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7" class="atk-empty">No detections yet — run a scenario</td></tr>';
    return;
  }
  body.innerHTML = rows.map(r => {
    const ok = (r.proactive_ok || 0) + (r.reactive_ok || 0) || (r.prevent_ok || 0);
    return rowHtml(r.attack, r.detections || 0, r.windows_detected || 0, r.gt_windows || 0,
                   r.proactive_blocks || 0, r.reactive_recovers || 0, ok,
                   !!r.misprediction, r.note);
  }).join('');
}
function push(chart, di, x, y) {
  const ds = chart.data.datasets[di];
  ds.data.push({ x, y });
  while (ds.data.length > MAXPTS) ds.data.shift();
}
function resetLive() {
  for (const c of Object.values(charts)) { c.data.datasets.forEach(d => d.data = []); c.update('none'); }
  trailPts = []; if (trailLine) trailLine.geometry.setDrawRange(0, 0);
}

let _physN = 0;
function onPhys(d) {
  const t = d.t_rel;
  const alt = (d.z != null) ? -d.z : d.rel_alt;
  // twin + HUD every sample (~30 Hz) => fluid live motion
  updateTwin(d);
  $('hudAlt').textContent = (alt || 0).toFixed(1) + ' m';
  $('hudSpeed').textContent = (d.speed || 0).toFixed(1) + ' m/s';
  $('hudVspeed').textContent = (num(d.vertical_speed)).toFixed(1) + ' m/s';
  $('hudTilt').textContent = (num(d.tilt_mag) * 57.2958).toFixed(0) + '°';
  $('hudArmed').textContent = d.armed ? 'ARMED' : 'disarmed';
  $('hudArmed').style.color = d.armed ? '#ff8a5c' : '#8493ad';
  $('hudMode').textContent = modeName(d.custom_mode);
  $('hudPos').textContent = `${num(d.x).toFixed(0)}, ${num(d.y).toFixed(0)}`;
  if (d.batt_remaining != null) $('hudBatt').textContent = num(d.batt_remaining).toFixed(0) + ' %';
  else if (d.batt_voltage != null) $('hudBatt').textContent = num(d.batt_voltage).toFixed(1) + ' V';
  $('clock').textContent = `t = ${t.toFixed(1)} s`;
  // charts + map throttled to ~10 Hz to keep the browser smooth
  if ((_physN++ % 3) === 0) {
    if (alt != null) push(charts.alt, 0, t, alt);
    if (d.speed != null) push(charts.speed, 0, t, d.speed);
    if (d.horiz_speed != null) push(charts.speed, 1, t, d.horiz_speed);
    if (d.tilt_mag != null) push(charts.speed, 2, t, d.tilt_mag);
    if (d.raw_rate != null) push(charts.raw, 0, t, d.raw_rate);
    charts.alt.update('none'); charts.speed.update('none'); charts.raw.update('none');
    drawMap();
  }
}

function onNet(d) {
  const t = d.t_rel;
  push(charts.net, 0, t, d.pkt_rate); push(charts.net, 1, t, d.to_uav_count); push(charts.net, 2, t, d.from_uav_count);
  const mix = ['command_long_count', 'heartbeat_count', 'param_set_count', 'rc_override_count', 'gps_input_count', 'manual_control_count', 'set_mode_count', 'mission_count'];
  mix.forEach((k, i) => push(charts.mix, i, t, d[k] || 0));
  charts.net.update('none'); charts.mix.update('none');
}

function modeName(cm) {
  // PX4 custom_mode: main_mode in byte 2, sub_mode (AUTO) in byte 3
  if (!cm) return '—';
  const main = (cm >> 16) & 0xFF, sub = (cm >> 24) & 0xFF;
  const M = { 1: 'MANUAL', 2: 'ALTCTL', 3: 'POSCTL', 4: 'AUTO', 5: 'ACRO', 6: 'OFFBOARD', 7: 'STABILIZED', 8: 'RATTITUDE' };
  const S = { 1: 'READY', 2: 'TAKEOFF', 3: 'LOITER', 4: 'MISSION', 5: 'RTL', 6: 'LAND', 7: 'RTGS', 8: 'FOLLOW', 9: 'PRECLAND' };
  if (main === 4) return 'AUTO.' + (S[sub] || sub);
  return M[main] || ('mode ' + main);
}

// ---------------------------------------------------------------- dataset browser
let DS = { layer: 'physical', kind: 'processed' };
let dsCharts = [];
let dsSig = '';
let dsTimer = null;
async function loadRuns(autopick) {
  const r = await fetch('/api/runs'); const d = await r.json();
  const sel = $('dsRun'); const prev = sel.value;
  sel.innerHTML = '';
  for (const run of d.runs) {
    const o = document.createElement('option');
    o.value = `${run.scenario}|${run.run}`;
    const nWin = run.n_attack_windows || 0;
    const gateTxt = (run.n_attack_gates != null && run.n_normal_gates != null)
      ? ` · gates ${run.n_attack_gates}A/${run.n_normal_gates}N`
      : '';
    o.textContent = `${run.scenario} / ${run.run}` + (
      run.is_attack && nWin > 0
        ? `  (${nWin} attack window${nWin === 1 ? '' : 's'}${gateTxt})`
        : (run.is_attack && run.attack_start_rel != null
            ? `  (attack @${run.attack_start_rel.toFixed(1)}s)` : ''));
    sel.appendChild(o);
  }
  if (autopick && sel.options.length) sel.value = sel.options[sel.options.length - 1].value;
  else if (prev) sel.value = prev;
  if (sel.value) loadDataset();
}
$('dsRun').addEventListener('change', () => loadDataset());
$('refreshRuns').addEventListener('click', () => loadRuns(false));
$('dsAuto').addEventListener('change', () => { if (!$('dsAuto').checked) stopDsPolling(); });
$('dsLayer').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; DS.layer = b.dataset.layer; segOn('dsLayer', 'layer', DS.layer); dsSig = ''; loadDataset(); });
$('dsKind').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; DS.kind = b.dataset.kind; segOn('dsKind', 'kind', DS.kind); dsSig = ''; loadDataset(); });
function segOn(id, attr, val) { $(id).querySelectorAll('button').forEach(b => b.classList.toggle('on', b.dataset[attr] === val)); }

// ---- live dataset following (reads the growing CSV straight from disk) ----
function beginLiveDataset(scenario, runName) {
  activeRunKey = `${scenario}|${runName}`;
  loadRuns(false).then(() => {
    const sel = $('dsRun');
    if ([...sel.options].some(o => o.value === activeRunKey)) sel.value = activeRunKey;
    loadDataset();
    startDsPolling();
  });
}
function startDsPolling() {
  if (dsTimer || !$('dsAuto').checked) return;
  $('dsLive').classList.remove('hidden');
  dsTimer = setInterval(() => { if ($('dsAuto').checked) loadDataset(true); }, 2000);
}
function stopDsPolling() {
  if (dsTimer) { clearInterval(dsTimer); dsTimer = null; }
  $('dsLive').classList.add('hidden');
}
function finalizeDsPolling() {
  // catch the final flush + the network file that lands only at run end
  setTimeout(() => { loadRuns(false); }, 1500);
  setTimeout(stopDsPolling, 1800);
}

// Shade normal (green) vs each attack window (red). Supports multi-window 50/50 gates.
const shadePlugin = {
  id: 'shade',
  beforeDraw(chart, args, opts) {
    let windows = Array.isArray(opts.windows) ? opts.windows.filter(w => w && w.start != null && w.end != null && w.end > w.start) : [];
    if (!windows.length && opts.as != null && opts.ae != null) {
      windows = [{ start: opts.as, end: opts.ae }];
    }
    if (!windows.length) return;
    const { ctx, chartArea, scales } = chart;
    const y0 = chartArea.top, h = chartArea.bottom - chartArea.top;
    const px = (t) => scales.x.getPixelForValue(t);
    const pe = opts.pe;
    const tMin = Math.min(0, ...windows.map(w => w.start));
    const tMax = pe != null ? pe : Math.max(...windows.map(w => w.end));
    ctx.save();
    // Full span green (normal), then paint each attack window red on top.
    if (tMax > tMin) {
      ctx.fillStyle = 'rgba(56,211,159,0.08)';
      ctx.fillRect(px(tMin), y0, px(tMax) - px(tMin), h);
    }
    ctx.fillStyle = 'rgba(255,77,94,0.16)';
    for (const w of windows) {
      ctx.fillRect(px(w.start), y0, px(w.end) - px(w.start), h);
    }
    ctx.restore();
  }
};

function shadeOpts(d) {
  const windows = (d.attack_windows || []).map(w => ({ start: w.start, end: w.end }));
  return { windows, as: d.attack_start, ae: d.attack_end, pe: d.post_end };
}

function dsInfoText(d) {
  const wins = d.attack_windows || [];
  if (wins.length) {
    const parts = wins.map((w, i) => `#${i + 1} ${Number(w.start).toFixed(1)}–${Number(w.end).toFixed(1)}s`);
    const gate = (d.n_attack_gates != null && d.n_normal_gates != null)
      ? ` · mid-WP gates ${d.n_attack_gates} attack / ${d.n_normal_gates} normal`
      : '';
    return `normal (green) · ${wins.length} attack window${wins.length === 1 ? '' : 's'} (red): ${parts.join(', ')}${gate}`;
  }
  if (d.attack_start != null) {
    return `normal plan (green) · attack ${d.attack_start.toFixed(1)}–${(d.attack_end || 0).toFixed(1)}s (red) · normal plan resume (green)`;
  }
  return 'benign — full normal plan';
}

async function loadDataset(live) {
  const sel = $('dsRun'); if (!sel.value) return;
  const [scenario, run] = sel.value.split('|');
  let r;
  try {
    r = await fetch(`/api/dataset?scenario=${scenario}&run=${run}&layer=${DS.layer}&kind=${DS.kind}`);
  } catch { return; }
  if (!r.ok) {
    if (!live) { $('dsPanels').innerHTML = '<div class="ds-info">no data yet for this selection (still recording?)</div>'; dsSig = ''; }
    return;
  }
  const d = await r.json();
  const panels = d.panels || [];
  const sig = `${sel.value}|${DS.layer}|${DS.kind}|` +
    panels.map(p => (p.series || []).map(s => s.name).join(',')).join(';');

  $('dsInfo').textContent = dsInfoText(d);

  // live + same structure -> update data in place (no flicker)
  if (live && sig === dsSig && dsCharts.length === panels.length) {
    panels.forEach((panel, pi) => {
      const c = dsCharts[pi];
      (panel.series || []).forEach((s, i) => {
        if (c.data.datasets[i]) c.data.datasets[i].data = s.points.map(p => ({ x: p[0], y: p[1] }));
      });
      c.options.plugins.shade = shadeOpts(d);
      c.update('none');
    });
    return;
  }

  // structure changed -> rebuild
  dsCharts.forEach(c => c.destroy()); dsCharts = [];
  dsSig = sig;
  const host = $('dsPanels'); host.innerHTML = '';
  panels.forEach((panel, pi) => {
    const card = document.createElement('div'); card.className = 'ds-card';
    const cid = `dsc_${pi}`;
    card.innerHTML = `<h4>${panel.title}</h4><canvas id="${cid}"></canvas>`;
    host.appendChild(card);
    const c = new Chart($(cid), {
      type: 'line',
      data: { datasets: (panel.series || []).map((s, i) => ({ label: s.name, data: s.points.map(p => ({ x: p[0], y: p[1] })), borderColor: PALETTE[i % PALETTE.length], backgroundColor: PALETTE[i % PALETTE.length], borderWidth: 1.4, pointRadius: 0, tension: .2, spanGaps: true })) },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false,
        scales: { x: { type: 'linear', title: { display: true, text: d.x_label } }, y: { ticks: { maxTicksLimit: 6 } } },
        plugins: { legend: { labels: { boxWidth: 10, padding: 6 } },
                   shade: shadeOpts(d) }
      },
      plugins: [shadePlugin]
    });
    dsCharts.push(c);
  });
  if (!panels.length) { host.innerHTML = '<div class="ds-info">no series in this file</div>'; dsSig = ''; }
}

// ---------------------------------------------------------------- pipeline modal
let pipeScope = 'core', pipeProfile = 'mission';
if ($('tourBtn')) {
  $('tourBtn').addEventListener('click', async () => {
    if (RUNNING) return;
    if (!confirm('Start multi-attack tour?\n\nExtended mission with ALL Tier-A attacks at evenly spaced mid-mission waypoints (same shared plan).\nUse Defense ON/OFF to compare active mitigation.\n\nThis flight is longer than a single scenario.')) return;
    RUNNING = true; updateRunButtons();
    try {
      const r = await fetch('/api/multi-tour', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ network: $('netToggle').checked })
      });
      const d = await r.json();
      if (!d.ok) {
        RUNNING = false; updateRunButtons();
        addLog({ tag: 'dashboard', msg: 'tour failed: ' + (d.message || 'unknown'), ts: Date.now() / 1000 });
        if (isCaptureError(d.message)) showCapModal(() => $('tourBtn').click());
        return;
      }
      if (d.schedule_preview) {
        ATTACK_GATES = new Set(d.schedule_preview.map(e => e.after_wp));
        drawMissionRoute();
        addLog({ tag: 'dashboard', msg: 'tour schedule: ' +
          d.schedule_preview.map(e => `${e.wp_id}→${e.attack}`).join(', '),
          ts: Date.now() / 1000 });
      }
    } catch (e) {
      RUNNING = false; updateRunButtons();
      addLog({ tag: 'dashboard', msg: 'tour error: ' + e, ts: Date.now() / 1000 });
    }
  });
}
$('pipelineBtn').addEventListener('click', () => {
  if (RUNNING) return;
  pipeProfile = PROFILE;
  segOnGeneric('pipeProfile', 'profile', pipeProfile);
  segOnGeneric('pipeScope', 'scope', pipeScope);
  $('pipeErr').classList.add('hidden');
  $('pipeModal').classList.remove('hidden');
  updateEstimate();
});
$('pipeCancel').addEventListener('click', () => $('pipeModal').classList.add('hidden'));
$('pipeModal').addEventListener('click', (e) => { if (e.target.id === 'pipeModal') $('pipeModal').classList.add('hidden'); });
$('pipeScope').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; pipeScope = b.dataset.scope; segOnGeneric('pipeScope', 'scope', pipeScope); updateEstimate(); });
$('pipeProfile').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; pipeProfile = b.dataset.profile; segOnGeneric('pipeProfile', 'profile', pipeProfile); });
$('pipeRuns').addEventListener('input', updateEstimate);
function segOnGeneric(id, attr, val) { $(id).querySelectorAll('button').forEach(b => b.classList.toggle('on', b.dataset[attr] === val)); }

function scenarioCount() {
  if (pipeScope === 'benign') return 1;
  const coreAttacks = SCENARIOS.filter(s => s.is_attack && s.tier === 'A').length;
  const support = SCENARIOS.filter(s => s.is_attack && s.tier === 'B').length;
  if (pipeScope === 'attacks') return coreAttacks;
  if (pipeScope === 'core') return coreAttacks + 1;
  return coreAttacks + support + 1; // all
}
function updateEstimate() {
  const runs = Math.max(1, parseInt($('pipeRuns').value || '1', 10));
  const n = scenarioCount();
  const coreAttacks = SCENARIOS.filter(s => s.is_attack && s.tier === 'A').length;
  let perRun;
  if (pipeScope === 'benign') perRun = RUN_DURATION + 14;
  else if (pipeScope === 'attacks') perRun = ATTACK_RUN_DURATION + 14;
  else if (pipeScope === 'core')
    perRun = ((RUN_DURATION + coreAttacks * ATTACK_RUN_DURATION) / Math.max(1, n)) + 14;
  else
    perRun = ((RUN_DURATION + (SCENARIOS.filter(s => s.is_attack).length) * ATTACK_RUN_DURATION) / Math.max(1, n)) + 14;
  const total = n * runs;
  const mins = Math.round((total * perRun) / 60);
  $('pipeEstimate').textContent =
    `${n} scenarios × ${runs} runs = ${total} recordings · ≈ ${mins} min ` +
    `(shared mission · attack after WP${ATTACK_WP} · scope=${pipeScope})`;
}
$('pipeStart').addEventListener('click', async () => {
  const runs = Math.max(1, Math.min(50, parseInt($('pipeRuns').value || '1', 10)));
  const body = { runs, scope: pipeScope, profile: pipeProfile, network: $('pipeNet').checked };
  const r = await fetch('/api/pipeline', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  const d = await r.json();
  if (!d.ok) {
    addLog({ tag: 'dashboard', msg: d.message, ts: Date.now() / 1000 });
    if (isCaptureError(d.message)) {
      openCaptureSetup(() => $('pipeStart').click());
    } else {
      const e = $('pipeErr'); e.textContent = d.message; e.classList.remove('hidden');
    }
    return;
  }
  $('pipeErr').classList.add('hidden');
  $('pipeModal').classList.add('hidden');
  RUNNING = true; PIPELINE = true; updateRunButtons(); resetLive();
  showPipeProgress(); setPipe(0, 0, 'starting…');
});

// -------------------------------------------------- network-capture setup
function isCaptureError(msg) { return /sudo|network capture/i.test(msg || ''); }
let pendingRetry = null;
function openCaptureSetup(retryFn) {
  pendingRetry = retryFn || null;
  const e = $('capErr'); e.textContent = ''; e.classList.add('hidden');
  $('capPass').value = '';
  $('capModal').classList.remove('hidden');
  setTimeout(() => $('capPass').focus(), 50);
}
function showCapErr(m) { const e = $('capErr'); e.textContent = m; e.classList.remove('hidden'); }
$('capCancel').addEventListener('click', () => { $('capModal').classList.add('hidden'); pendingRetry = null; });
$('capModal').addEventListener('click', (e) => { if (e.target.id === 'capModal') { $('capModal').classList.add('hidden'); pendingRetry = null; } });
$('capPass').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('capEnable').click(); });
$('capEnable').addEventListener('click', async () => {
  const pw = $('capPass').value;
  if (!pw) { showCapErr('enter your Mac login password'); return; }
  const btn = $('capEnable'); btn.disabled = true; btn.textContent = 'enabling…';
  try {
    const r = await fetch('/api/setup-capture', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw })
    });
    const d = await r.json();
    if (!d.ok) { showCapErr(d.message || 'setup failed'); return; }
    addLog({ tag: 'dashboard', msg: 'network capture enabled ✓', ts: Date.now() / 1000 });
    $('capModal').classList.add('hidden');
    const retry = pendingRetry; pendingRetry = null;
    if (retry) setTimeout(retry, 150);
  } catch (err) { showCapErr(String(err)); }
  finally { btn.disabled = false; btn.textContent = 'Enable capture'; }
});

// ---------------------------------------------------------------- boot
initTwin();
initCharts();
loadScenarios();
loadRuns(false);
fetch('/api/ids').then(r => r.json()).then(setIdsStatus).catch(() => {});
function refreshPt() {
  fetch('/api/pt').then(r => r.json()).then(onPt).catch(() => {});
}
refreshPt();
setInterval(refreshPt, 5000);
connect();
