const PUBLIC_CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const ADMIN_COOKIE = "cm_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;
const encoder = new TextEncoder();

function publicJson(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { ...PUBLIC_CORS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function denied() {
  return publicJson({ status: false, reason: "Invalid license key!" });
}

function adminJson(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extraHeaders },
  });
}

function utcString(date) {
  return date.toISOString().slice(0, 19).replace("T", " ");
}

function utcMillis(value) {
  if (!value) return NaN;
  const text = String(value);
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(text)
    ? `${text.replace(" ", "T")}Z`
    : text;
  return Date.parse(normalized);
}

function randomHex(bytesLength) {
  const bytes = new Uint8Array(bytesLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomLicenseKey() {
  return `CM-${randomHex(16).toUpperCase()}`;
}

async function readFields(request) {
  const type = request.headers.get("Content-Type") || "";
  if (type.includes("application/json")) {
    const body = await request.json();
    return {
      game: String(body.game || "").trim(),
      user_key: String(body.user_key || "").trim(),
      serial: String(body.serial || "").trim(),
    };
  }
  const form = new URLSearchParams(await request.text());
  return {
    game: String(form.get("game") || "").trim(),
    user_key: String(form.get("user_key") || "").trim(),
    serial: String(form.get("serial") || "").trim(),
  };
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function validSerial(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 300 && !/[\u0000-\u001f\u007f]/.test(value);
}

function validUserKey(value) {
  return typeof value === "string" && value.length > 0 && Array.from(value).length <= 120 && !/\p{Cc}/u.test(value);
}

function b64url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromB64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function cookieValue(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return "";
}

function secretsReady(env) {
  return typeof env.ADMIN_PASSWORD === "string" && env.ADMIN_PASSWORD.length >= 16 &&
    typeof env.ADMIN_SESSION_SECRET === "string" && env.ADMIN_SESSION_SECRET.length >= 32;
}

async function makeSession(env) {
  const payload = b64url(encoder.encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS, nonce: randomHex(12) })));
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.ADMIN_SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return `${payload}.${b64url(signature)}`;
}

async function validSession(request, env) {
  if (!secretsReady(env)) return false;
  const token = cookieValue(request, ADMIN_COOKIE);
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(env.ADMIN_SESSION_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const good = await crypto.subtle.verify("HMAC", key, fromB64url(parts[1]), encoder.encode(parts[0]));
    if (!good) return false;
    const payload = JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
    return Number.isInteger(payload.exp) && payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function passwordMatches(candidate, expected) {
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(candidate)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let difference = 0;
  for (let i = 0; i < x.length; i++) difference |= x[i] ^ y[i];
  return difference === 0;
}

function sameOrigin(request) {
  return request.headers.get("Origin") === new URL(request.url).origin;
}

function sessionCookie(value) {
  return `${ADMIN_COOKIE}=${value}; Path=/admin; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Strict`;
}

function clearSessionCookie() {
  return `${ADMIN_COOKIE}=; Path=/admin; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

const ADMIN_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#101827">
<title>License Admin</title>
<style>
:root{color-scheme:dark;--bg:#0b1220;--panel:#111c2e;--panel2:#16243a;--text:#edf3ff;--muted:#a8b6cc;--line:#2a3b55;--accent:#72e0bd;--red:#ff8585;--yellow:#ffd479}*{box-sizing:border-box}body{margin:0;background:linear-gradient(155deg,#0c1527,#080d17 65%);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}.wrap{max-width:1100px;margin:auto;padding:16px}.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:6px 0 18px}.brand{font-size:21px;font-weight:750;letter-spacing:.2px}.sub{color:var(--muted);font-size:13px}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px;margin:14px 0;box-shadow:0 12px 34px #0003}.card h1,.card h2{margin:0 0 12px}.card h1{font-size:22px}.card h2{font-size:18px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.stat{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:13px}.stat strong{display:block;font-size:21px}.stat span{color:var(--muted);font-size:12px}label{display:block;color:var(--muted);font-size:13px;margin:0 0 5px}input{width:100%;background:#0b1423;color:var(--text);border:1px solid #344965;border-radius:10px;padding:12px;font:inherit;min-height:44px}input:focus{outline:2px solid #72e0bd66;border-color:var(--accent)}button{background:#20324c;color:var(--text);border:1px solid #3a5271;border-radius:10px;padding:10px 13px;font:inherit;font-weight:650;min-height:42px;cursor:pointer}button.primary{background:var(--accent);color:#062017;border-color:var(--accent)}button.danger{color:#ffdada;border-color:#9e4c5b;background:#452331}button.small{min-height:34px;padding:6px 9px;font-size:12px}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.formgrid{display:grid;grid-template-columns:2fr 1.5fr 1fr 1fr;gap:12px;align-items:end}.msg{display:none;border-radius:10px;padding:11px 13px;margin:10px 0;background:#243951;color:var(--text)}.msg.error{display:block;background:#43232b;color:#ffd7d7}.msg.ok{display:block;background:#173b34;color:#d6fff3}.hint{color:var(--muted);font-size:12px;margin-top:8px}.created{display:none;margin-top:12px;padding:12px;border:1px solid #31785e;border-radius:12px;background:#102a26}.created code{display:block;word-break:break-all;font-size:16px;margin:6px 0}.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-bottom:12px}.toolbar input{max-width:360px}.tablewrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:760px}th,td{text-align:left;padding:11px 9px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--muted);font-weight:650}td code{word-break:break-all;color:#d7e6ff}.pill{display:inline-block;padding:3px 8px;border:1px solid var(--line);border-radius:99px;font-size:11px}.pill.good{color:#aaffdd;border-color:#31785e}.pill.bad{color:#ffc3c3;border-color:#8d4e59}.devices{padding:8px 0}.device{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;border-top:1px solid var(--line);padding:9px 0}.deviceinfo{min-width:0}.deviceinfo code{display:block;word-break:break-all}.deviceinfo small{color:var(--muted)}.empty{color:var(--muted);padding:15px}.footer{color:var(--muted);font-size:12px;padding:4px 2px 20px}.hidden{display:none!important}@media(max-width:760px){.wrap{padding:12px}.grid,.formgrid{grid-template-columns:1fr 1fr}.stats{grid-template-columns:1fr 1fr}.card{padding:14px}.brand{font-size:19px}.toolbar{align-items:stretch;flex-direction:column}.toolbar input{max-width:none}.device{flex-direction:column}.actions button{flex:1}}
</style>
</head>
<body>
<div class="wrap">
  <header class="top"><div><div class="brand">License Admin</div><div class="sub">Key issuing, expiry, device limits and device access</div></div><button id="logoutBtn" class="hidden">Log out</button></header>
  <div id="message" class="msg"></div>
  <section id="loginCard" class="card">
    <h1>Admin sign in</h1><p class="sub">Use the admin password configured in Cloudflare Worker Secrets.</p>
    <form id="loginForm"><label for="password">Admin password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256"><div style="height:12px"></div><button class="primary" type="submit">Sign in</button></form>
  </section>
  <main id="panel" class="hidden">
    <section class="stats">
      <div class="stat"><strong id="totalKeys">0</strong><span>Total keys</span></div>
      <div class="stat"><strong id="enabledKeys">0</strong><span>Enabled keys</span></div>
      <div class="stat"><strong id="registeredDevices">0</strong><span>Bound device slots</span></div>
    </section>
    <section class="card">
      <h2>Create license key</h2>
      <form id="createForm">
        <div class="formgrid">
          <div><label for="real">Label / owner name</label><input id="real" name="real" placeholder="e.g. Arafat" required maxlength="120"></div>
          <div><label for="customKey">Key (optional; blank = generate)</label><input id="customKey" name="user_key" placeholder="Auto-generate a secure key" maxlength="120"></div>
          <div><label for="days">Valid for (days)</label><input id="days" name="days" type="number" min="1" max="3650" value="30" required></div>
          <div><label for="maxDevices">Device limit</label><input id="maxDevices" name="max_devices" type="number" min="1" step="1" value="1" required></div>
        </div>
        <div style="height:12px"></div><button class="primary" type="submit">Create key</button>
      </form>
      <div id="created" class="created"><strong>Key created — copy it now</strong><code id="createdValue"></code><button id="copyKey" class="small" type="button">Copy key</button></div>
      <p class="hint">Expiry is calculated from creation time in UTC. A device is counted after its first successful verification.</p>
    </section>
    <section class="card">
      <div class="toolbar"><div><h2 style="margin:0">Licenses and devices</h2><div class="hint">“Eligible devices” means registered device IDs, not a live count of apps currently open.</div></div><div class="actions"><input id="search" type="search" placeholder="Search key or label"><button id="refreshBtn" type="button">Refresh</button></div></div>
      <div id="licenseList" class="tablewrap"><div class="empty">Loading…</div></div>
    </section>
  </main>
  <div class="footer">Keep this admin password private. Device IDs are app-provided identifiers and may be spoofable; they are not hardware attestation.</div>
</div>
<script>
(function(){
  var loginCard=document.getElementById('loginCard');
  var panel=document.getElementById('panel');
  var message=document.getElementById('message');
  var logoutBtn=document.getElementById('logoutBtn');
  var licenses=[];
  function say(text,bad){message.textContent=text;message.className='msg '+(bad?'error':'ok');}
  function clearSay(){message.textContent='';message.className='msg';}
  function showLogin(){loginCard.classList.remove('hidden');panel.classList.add('hidden');logoutBtn.classList.add('hidden');}
  function showPanel(){loginCard.classList.add('hidden');panel.classList.remove('hidden');logoutBtn.classList.remove('hidden');}
  async function api(path,method,body){
    var options={method:method||'GET',credentials:'same-origin',headers:{'Accept':'application/json'}};
    if(body!==undefined){options.headers['Content-Type']='application/json';options.body=JSON.stringify(body);}
    var response=await fetch(path,options);var data={};try{data=await response.json();}catch(e){}
    if(!response.ok){var error=new Error(data.error||('Request failed ('+response.status+')'));error.status=response.status;throw error;}
    return data;
  }
  function addCell(row,text){var cell=document.createElement('td');cell.textContent=text==null?'':String(text);row.appendChild(cell);return cell;}
  function makeButton(text,klass,handler){var button=document.createElement('button');button.type='button';button.textContent=text;button.className='small '+(klass||'');button.addEventListener('click',handler);return button;}
  function render(){
    var query=document.getElementById('search').value.trim().toLowerCase();
    var filtered=licenses.filter(function(item){return (item.user_key+' '+item.real).toLowerCase().indexOf(query)>=0;});
    document.getElementById('totalKeys').textContent=String(licenses.length);
    document.getElementById('enabledKeys').textContent=String(licenses.filter(function(item){return Number(item.active)===1;}).length);
    document.getElementById('registeredDevices').textContent=String(licenses.reduce(function(n,item){return n+Number(item.device_count||0);},0));
    var root=document.getElementById('licenseList');root.textContent='';
    if(!filtered.length){var empty=document.createElement('div');empty.className='empty';empty.textContent='No matching licenses.';root.appendChild(empty);return;}
    var table=document.createElement('table');var head=document.createElement('thead');var hr=document.createElement('tr');
    ['Key / label','Expiry (UTC)','Devices','Status','Actions'].forEach(function(label){var th=document.createElement('th');th.textContent=label;hr.appendChild(th);});head.appendChild(hr);table.appendChild(head);
    var body=document.createElement('tbody');
    filtered.forEach(function(item){
      var row=document.createElement('tr');var keyCell=addCell(row,'');var key=document.createElement('code');key.textContent=item.user_key;keyCell.appendChild(key);var label=document.createElement('div');label.className='sub';label.textContent=item.real;keyCell.appendChild(label);
      addCell(row,item.expires_at+' UTC');
      var devCell=addCell(row,String(item.device_count||0)+' / '+String(item.max_devices));
      if(item.devices&&item.devices.length){
        var details=document.createElement('details');var summary=document.createElement('summary');summary.textContent='Device list ('+item.devices.length+')';details.appendChild(summary);var list=document.createElement('div');list.className='devices';
        item.devices.forEach(function(device){
          var box=document.createElement('div');box.className='device';var info=document.createElement('div');info.className='deviceinfo';var serial=document.createElement('code');serial.textContent=device.serial;info.appendChild(serial);var small=document.createElement('small');small.textContent='Last verified: '+device.last_seen_at+' UTC'+(Number(device.blocked)===1?' • blocked for this key':'')+(device.banned?' • globally banned':'')+(device.allowed?'':' • over device limit');info.appendChild(small);box.appendChild(info);
          var controls=document.createElement('div');controls.className='actions';
          controls.appendChild(makeButton(device.banned?'Unban device':'Ban device',device.banned?'':'danger',async function(){try{if(device.banned){await api('/admin/api/device/unban','POST',{serial:device.serial});}else{if(!confirm('Ban this device ID across all licenses?'))return;await api('/admin/api/device/ban','POST',{serial:device.serial,note:'Blocked from admin panel'});}await refresh();}catch(e){say(e.message,true);}}));
          controls.appendChild(makeButton('Unbind', 'danger',async function(){if(!confirm('Remove this device from this license? It will free one slot.'))return;try{await api('/admin/api/device/unbind','POST',{user_key:item.user_key,serial:device.serial});await refresh();}catch(e){say(e.message,true);}}));
          box.appendChild(controls);list.appendChild(box);
        });details.appendChild(list);devCell.appendChild(details);
      }
      var statusCell=addCell(row,'');var status=document.createElement('span');status.className='pill '+(Number(item.active)===1?'good':'bad');status.textContent=Number(item.active)===1?'Enabled':'Revoked';statusCell.appendChild(status);
      var actionCell=addCell(row,'');var actions=document.createElement('div');actions.className='actions';
      actions.appendChild(makeButton(Number(item.active)===1?'Revoke':'Enable',Number(item.active)===1?'danger':'',async function(){try{await api('/admin/api/license/status','POST',{user_key:item.user_key,active:Number(item.active)!==1});await refresh();}catch(e){say(e.message,true);}}));
      actions.appendChild(makeButton('Adjust', '',async function(){var days=prompt('Add validity days (enter 0 to leave expiry unchanged):','0');if(days===null)return;var limit=prompt('Set maximum devices (positive whole number):',String(item.max_devices));if(limit===null)return;try{await api('/admin/api/license/update','POST',{user_key:item.user_key,add_days:Number(days),max_devices:Number(limit)});await refresh();say('License updated.',false);}catch(e){say(e.message,true);}}));
      actionCell.appendChild(actions);body.appendChild(row);
    });
    table.appendChild(body);root.appendChild(table);
  }
  async function refresh(){
    try{var result=await api('/admin/api/licenses','GET');licenses=result.licenses||[];showPanel();render();clearSay();}
    catch(e){if(e.status===401){showLogin();return;}say(e.message,true);}
  }
  document.getElementById('loginForm').addEventListener('submit',async function(event){event.preventDefault();clearSay();var pass=document.getElementById('password');try{await api('/admin/login','POST',{password:pass.value});pass.value='';await refresh();say('Signed in.',false);}catch(e){say(e.message,true);}});
  document.getElementById('createForm').addEventListener('submit',async function(event){event.preventDefault();clearSay();var form=event.currentTarget;var payload={real:form.elements.real.value.trim(),user_key:form.elements.user_key.value.trim(),days:Number(form.elements.days.value),max_devices:Number(form.elements.max_devices.value)};try{var result=await api('/admin/api/license/create','POST',payload);document.getElementById('createdValue').textContent=result.user_key;document.getElementById('created').style.display='block';form.elements.user_key.value='';await refresh();say('License key created. Copy it from the green box.',false);}catch(e){say(e.message,true);}});
  document.getElementById('copyKey').addEventListener('click',async function(){var text=document.getElementById('createdValue').textContent;try{await navigator.clipboard.writeText(text);say('Key copied.',false);}catch(e){window.prompt('Copy this license key:',text);}});
  document.getElementById('refreshBtn').addEventListener('click',refresh);
  document.getElementById('search').addEventListener('input',render);
  logoutBtn.addEventListener('click',async function(){try{await api('/admin/logout','POST',{});}catch(e){}showLogin();say('Signed out.',false);});
  refresh();
})();
</script>
</body>
</html>`;

async function verifyLicense(request, env) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: PUBLIC_CORS });
  if (request.method !== "POST") return denied();
  let fields;
  try {
    fields = await readFields(request);
  } catch {
    return denied();
  }

  const { game, user_key, serial } = fields;
  if (game !== "FreeFire" || !validUserKey(user_key) || !validSerial(serial)) return denied();

  try {
    const license = await env.DB.prepare(
      `SELECT user_key, active, expires_at, real, modname, mod_status, credit, max_devices
       FROM licenses WHERE user_key = ?1`
    ).bind(user_key).first();
    if (!license || Number(license.active) !== 1) return denied();
    const expiresAt = utcMillis(license.expires_at);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return denied();

    const ban = await env.DB.prepare("SELECT serial FROM banned_devices WHERE serial = ?1").bind(serial).first();
    if (ban) return denied();

    let device = await env.DB.prepare(
      "SELECT serial, blocked FROM license_devices_v2 WHERE user_key = ?1 AND serial = ?2"
    ).bind(user_key, serial).first();
    if (device && Number(device.blocked) === 1) return denied();

    const now = utcString(new Date());
    if (!device) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO license_devices_v2 (user_key, serial, first_seen_at, last_seen_at, blocked)
         SELECT ?1, ?2, ?3, ?3, 0
         WHERE (SELECT COUNT(*) FROM license_devices_v2 d
                WHERE d.user_key = ?4 AND d.blocked = 0
                  AND NOT EXISTS (SELECT 1 FROM banned_devices b WHERE b.serial = d.serial))
               < (SELECT max_devices FROM licenses WHERE user_key = ?5)`
      ).bind(user_key, serial, now, user_key, user_key).run();

      device = await env.DB.prepare(
        "SELECT serial, blocked FROM license_devices_v2 WHERE user_key = ?1 AND serial = ?2"
      ).bind(user_key, serial).first();
      if (!device || Number(device.blocked) === 1) return denied();
    }

    const allowedDevices = await env.DB.prepare(
      `SELECT d.serial FROM license_devices_v2 d
       WHERE d.user_key = ?1 AND d.blocked = 0
         AND NOT EXISTS (SELECT 1 FROM banned_devices b WHERE b.serial = d.serial)
       ORDER BY d.first_seen_at ASC, d.serial ASC LIMIT ?2`
    ).bind(user_key, Number(license.max_devices)).all();
    if (!(allowedDevices.results || []).some((entry) => entry.serial === serial)) return denied();

    await env.DB.prepare(
      "UPDATE license_devices_v2 SET last_seen_at = ?1 WHERE user_key = ?2 AND serial = ?3"
    ).bind(now, user_key, serial).run();

    return publicJson({
      status: true,
      data: {
        modname: license.modname || "CrackMaster",
        mod_status: license.mod_status || "Safe",
        credit: license.credit || "CrackMaster",
        expired_date: license.expires_at,
        real: license.real,
        token: randomHex(16),
      },
    });
  } catch {
    return denied();
  }
}

async function adminLogin(request, env) {
  if (!sameOrigin(request)) return adminJson({ error: "Invalid request origin." }, 403);
  if (!secretsReady(env)) return adminJson({ error: "Set ADMIN_PASSWORD and ADMIN_SESSION_SECRET in Worker Secrets first." }, 503);
  const body = await readJson(request);
  const candidate = body && typeof body.password === "string" ? body.password : "";
  if (candidate.length > 256 || !(await passwordMatches(candidate, env.ADMIN_PASSWORD))) {
    return adminJson({ error: "Incorrect password." }, 401);
  }
  const token = await makeSession(env);
  return adminJson({ ok: true }, 200, { "Set-Cookie": sessionCookie(token) });
}

async function adminListLicenses(env) {
  if (!env.DB) return adminJson({ error: "D1 binding DB is missing." }, 503);
  const [licenseResult, deviceResult] = await Promise.all([
    env.DB.prepare(
      `SELECT user_key, active, expires_at, real, max_devices, modname, mod_status, credit, created_at
       FROM licenses ORDER BY created_at DESC LIMIT 1000`
    ).all(),
    env.DB.prepare(
      `SELECT d.user_key, d.serial, d.first_seen_at, d.last_seen_at, d.blocked,
              CASE WHEN b.serial IS NULL THEN 0 ELSE 1 END AS banned
       FROM license_devices_v2 d LEFT JOIN banned_devices b ON b.serial = d.serial
       ORDER BY d.user_key, d.first_seen_at`
    ).all(),
  ]);
  const devicesByKey = new Map();
  for (const device of deviceResult.results || []) {
    if (!devicesByKey.has(device.user_key)) devicesByKey.set(device.user_key, []);
    devicesByKey.get(device.user_key).push(device);
  }
  const licenses = (licenseResult.results || []).map((license) => {
    const devices = devicesByKey.get(license.user_key) || [];
    const eligible = devices.filter((device) => Number(device.blocked) === 0 && Number(device.banned) === 0)
      .sort((a, b) => String(a.first_seen_at).localeCompare(String(b.first_seen_at)) || String(a.serial).localeCompare(String(b.serial)));
    const allowed = new Set(eligible.slice(0, Math.max(1, Number(license.max_devices) || 1)).map((device) => device.serial));
    const listedDevices = devices.map((device) => ({ ...device, allowed: allowed.has(device.serial) }));
    return { ...license, device_count: allowed.size, devices: listedDevices };
  });
  return adminJson({ licenses });
}

async function adminCreateLicense(request, env) {
  const body = await readJson(request);
  if (!body || typeof body !== "object") return adminJson({ error: "Invalid input." }, 400);
  const real = typeof body.real === "string" ? body.real.trim() : "";
  const suppliedKey = typeof body.user_key === "string" ? body.user_key.trim() : "";
  const days = Number(body.days);
  const maxDevices = Number(body.max_devices);
  if (!real || real.length > 120) return adminJson({ error: "Enter a label/name up to 120 characters." }, 400);
  if (!Number.isInteger(days) || days < 1 || days > 3650) return adminJson({ error: "Days must be an integer from 1 to 3650." }, 400);
  if (!Number.isSafeInteger(maxDevices) || maxDevices < 1) return adminJson({ error: "Device limit must be a positive whole number." }, 400);
  if (suppliedKey && !validUserKey(suppliedKey)) return adminJson({ error: "Custom key must be 1–120 characters; control characters are not allowed." }, 400);

  const expiry = utcString(new Date(Date.now() + days * 86400000));
  const generated = !suppliedKey;
  let userKey = suppliedKey || randomLicenseKey();
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await env.DB.prepare(
        `INSERT INTO licenses (user_key, active, expires_at, real, max_devices)
         VALUES (?1, 1, ?2, ?3, ?4)`
      ).bind(userKey, expiry, real, maxDevices).run();
      return adminJson({ ok: true, user_key: userKey, expires_at: expiry, real, max_devices: maxDevices });
    } catch {
      if (!generated) return adminJson({ error: "That key already exists or could not be saved." }, 409);
      userKey = randomLicenseKey();
    }
  }
  return adminJson({ error: "Could not generate a unique key; try again." }, 500);
}

async function adminUpdateLicense(request, env) {
  const body = await readJson(request);
  const userKey = body && typeof body.user_key === "string" ? body.user_key.trim() : "";
  if (!validUserKey(userKey)) return adminJson({ error: "Invalid license key." }, 400);
  const addDays = body.add_days === undefined ? 0 : Number(body.add_days);
  const maxDevices = body.max_devices === undefined ? null : Number(body.max_devices);
  if (!Number.isInteger(addDays) || addDays < 0 || addDays > 3650) return adminJson({ error: "Add-days must be an integer from 0 to 3650." }, 400);
  if (maxDevices !== null && (!Number.isSafeInteger(maxDevices) || maxDevices < 1)) return adminJson({ error: "Device limit must be a positive whole number." }, 400);
  if (addDays === 0 && maxDevices === null) return adminJson({ error: "Provide days to add or a device limit." }, 400);
  const license = await env.DB.prepare("SELECT expires_at FROM licenses WHERE user_key = ?1").bind(userKey).first();
  if (!license) return adminJson({ error: "License not found." }, 404);
  let expiry = license.expires_at;
  if (addDays > 0) {
    const oldMillis = utcMillis(license.expires_at);
    const base = Math.max(Date.now(), Number.isFinite(oldMillis) ? oldMillis : Date.now());
    expiry = utcString(new Date(base + addDays * 86400000));
  }
  if (maxDevices === null) {
    await env.DB.prepare("UPDATE licenses SET expires_at = ?1 WHERE user_key = ?2").bind(expiry, userKey).run();
  } else {
    await env.DB.prepare("UPDATE licenses SET expires_at = ?1, max_devices = ?2 WHERE user_key = ?3").bind(expiry, maxDevices, userKey).run();
  }
  return adminJson({ ok: true, expires_at: expiry, max_devices: maxDevices });
}

async function adminSetLicenseStatus(request, env) {
  const body = await readJson(request);
  const userKey = body && typeof body.user_key === "string" ? body.user_key.trim() : "";
  if (!validUserKey(userKey) || typeof body.active !== "boolean") return adminJson({ error: "Invalid key/status." }, 400);
  const result = await env.DB.prepare("UPDATE licenses SET active = ?1 WHERE user_key = ?2").bind(body.active ? 1 : 0, userKey).run();
  if (!result.meta || result.meta.changes === 0) return adminJson({ error: "License not found." }, 404);
  return adminJson({ ok: true });
}

async function adminUnbindDevice(request, env) {
  const body = await readJson(request);
  const userKey = body && typeof body.user_key === "string" ? body.user_key.trim() : "";
  const serial = body && typeof body.serial === "string" ? body.serial : "";
  if (!validUserKey(userKey) || !validSerial(serial)) return adminJson({ error: "Invalid key/device ID." }, 400);
  await env.DB.prepare("DELETE FROM license_devices_v2 WHERE user_key = ?1 AND serial = ?2").bind(userKey, serial).run();
  return adminJson({ ok: true });
}

async function adminBanDevice(request, env) {
  const body = await readJson(request);
  const serial = body && typeof body.serial === "string" ? body.serial : "";
  const note = body && typeof body.note === "string" ? body.note.trim().slice(0, 200) : "";
  if (!validSerial(serial)) return adminJson({ error: "Invalid device ID." }, 400);
  await env.DB.prepare(
    `INSERT INTO banned_devices (serial, note, banned_at) VALUES (?1, ?2, ?3)
     ON CONFLICT(serial) DO UPDATE SET note = excluded.note, banned_at = excluded.banned_at`
  ).bind(serial, note, utcString(new Date())).run();
  return adminJson({ ok: true });
}

async function adminUnbanDevice(request, env) {
  const body = await readJson(request);
  const serial = body && typeof body.serial === "string" ? body.serial : "";
  if (!validSerial(serial)) return adminJson({ error: "Invalid device ID." }, 400);
  await env.DB.prepare("DELETE FROM banned_devices WHERE serial = ?1").bind(serial).run();
  return adminJson({ ok: true });
}

function adminPageResponse() {
  return new Response(ADMIN_HTML, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    },
  });
}

async function handleAdmin(request, env, url) {
  const path = url.pathname;
  if (path === "/admin" && request.method === "GET") {
    return Response.redirect(new URL("/admin/", url), 302);
  }
  if (path === "/admin/" && request.method === "GET") return adminPageResponse();

  if (path === "/admin/login" && request.method === "POST") return adminLogin(request, env);
  if (path === "/admin/logout" && request.method === "POST") {
    if (!sameOrigin(request)) return adminJson({ error: "Invalid request origin." }, 403);
    return adminJson({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
  }

  if (!path.startsWith("/admin/api/")) return new Response("Not found", { status: 404 });
  if (!secretsReady(env)) return adminJson({ error: "Admin secrets are not configured." }, 503);
  if (!(await validSession(request, env))) return adminJson({ error: "Sign-in required." }, 401);
  if (request.method === "POST" && !sameOrigin(request)) return adminJson({ error: "Invalid request origin." }, 403);
  if (!env.DB) return adminJson({ error: "D1 binding DB is missing." }, 503);

  try {
    if (path === "/admin/api/licenses" && request.method === "GET") return await adminListLicenses(env);
    if (path === "/admin/api/license/create" && request.method === "POST") return await adminCreateLicense(request, env);
    if (path === "/admin/api/license/update" && request.method === "POST") return await adminUpdateLicense(request, env);
    if (path === "/admin/api/license/status" && request.method === "POST") return await adminSetLicenseStatus(request, env);
    if (path === "/admin/api/device/unbind" && request.method === "POST") return await adminUnbindDevice(request, env);
    if (path === "/admin/api/device/ban" && request.method === "POST") return await adminBanDevice(request, env);
    if (path === "/admin/api/device/unban" && request.method === "POST") return await adminUnbanDevice(request, env);
    return new Response("Not found", { status: 404 });
  } catch {
    return adminJson({ error: "Database operation failed. Check that the one-time migration completed." }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/verify.php") return await verifyLicense(request, env);
    if (url.pathname === "/admin" || url.pathname.startsWith("/admin/")) return await handleAdmin(request, env, url);
    return new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  },
};
