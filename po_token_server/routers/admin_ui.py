"""Admin UI router: serves a single-page admin dashboard at /admin.

The dashboard is a self-contained HTML page (no external dependencies) that
lets admins manage users, API keys, and sessions via the /api/v1/admin/*
endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["admin-ui"])

_ADMIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PO Token Server — Admin</title>
<style>
  :root {
    --bg: #0f172a; --card: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --dim: #64748b;
    --blue: #3b82f6; --blue-h: #2563eb;
    --green: #34d399; --red: #f87171; --yellow: #fbbf24;
    --radius: 12px;
  }
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg);
         color: var(--text); margin: 0; min-height: 100vh; }
  .container { max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  .subtitle { color: var(--muted); font-size: .9rem; margin-bottom: 2rem; }
  .card { background: var(--card); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 1.5rem; margin-bottom: 1.5rem; }
  .card h2 { font-size: 1.1rem; margin: 0 0 1rem; color: var(--text); }
  .row { display: flex; gap: .75rem; align-items: center; flex-wrap: wrap; }
  .btn { padding: .55rem 1.1rem; border: none; border-radius: 8px;
         font-size: .85rem; font-weight: 600; cursor: pointer; transition: background .15s; }
  .btn-primary { background: var(--blue); color: #fff; }
  .btn-primary:hover { background: var(--blue-h); }
  .btn-danger { background: #dc2626; color: #fff; }
  .btn-danger:hover { background: #b91c1c; }
  .btn-sm { padding: .35rem .7rem; font-size: .78rem; }
  .btn:disabled { opacity: .5; cursor: not-allowed; }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  th { text-align: left; color: var(--dim); font-weight: 600; padding: .5rem .75rem;
       border-bottom: 1px solid var(--border); }
  td { padding: .6rem .75rem; border-bottom: 1px solid var(--border); }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: .15rem .5rem; border-radius: 6px;
           font-size: .72rem; font-weight: 600; }
  .badge-active { background: #065f46; color: var(--green); }
  .badge-suspended { background: #7f1d1d; color: var(--red); }
  .badge-admin { background: #1e3a5f; color: #93c5fd; }
  .badge-revoked { background: #7f1d1d; color: var(--red); }
  .badge-ok { background: #065f46; color: var(--green); }
  .empty { color: var(--dim); font-style: italic; padding: 1rem 0; text-align: center; }
  .toast { position: fixed; bottom: 1.5rem; right: 1.5rem; padding: .75rem 1.25rem;
           border-radius: 8px; font-size: .85rem; font-weight: 600; z-index: 100;
           opacity: 0; transition: opacity .3s; pointer-events: none; }
  .toast.show { opacity: 1; }
  .toast-ok { background: #065f46; color: var(--green); }
  .toast-err { background: #7f1d1d; color: var(--red); }
  .login-box { max-width: 400px; margin: 4rem auto; }
  .login-box input { width: 100%; padding: .7rem 1rem; border: 1px solid var(--border);
                     border-radius: 8px; background: var(--bg); color: var(--text);
                     font-size: .9rem; margin-bottom: .75rem; }
  .login-box input:focus { outline: none; border-color: var(--blue); }
  .status-bar { display: flex; justify-content: space-between; align-items: center;
               margin-bottom: 1.5rem; flex-wrap: wrap; gap: .5rem; }
  .status-bar .info { color: var(--muted); font-size: .82rem; }
  .key-display { background: var(--bg); padding: .5rem .75rem; border-radius: 6px;
                 font-family: monospace; font-size: .8rem; word-break: break-all;
                 border: 1px solid var(--border); margin-top: .5rem; }
  .section-header { display: flex; justify-content: space-between; align-items: center;
                    margin-bottom: .75rem; }
  select { padding: .4rem .6rem; border: 1px solid var(--border); border-radius: 6px;
           background: var(--bg); color: var(--text); font-size: .82rem; }
</style>
</head>
<body>
<div id="app" class="container"></div>
<div id="toast" class="toast"></div>

<script>
const API = '/api/v1/admin';
let token = localStorage.getItem('pot_admin_token') || '';
let currentUser = null;

// ── Helpers ──────────────────────────────────────────────────────────────
function toast(msg, ok = true) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show ' + (ok ? 'toast-ok' : 'toast-err');
  setTimeout(() => el.className = 'toast', 3000);
}

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...opts.headers };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const resp = await fetch(API + path, { ...opts, headers });
  if (resp.status === 401) {
    token = '';
    localStorage.removeItem('pot_admin_token');
    render();
    throw new Error('Unauthorized');
  }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.detail || resp.statusText);
  return data;
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString() + ' ' + new Date(iso).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
}

// ── Login ────────────────────────────────────────────────────────────────
function renderLogin() {
  document.getElementById('app').innerHTML = `
    <div class="card login-box">
      <h1>PO Token Server</h1>
      <p class="subtitle">Admin Dashboard</p>
      <form id="loginForm">
        <input type="email" id="loginEmail" placeholder="Email" required>
        <input type="password" id="loginPass" placeholder="Password" required>
        <button type="submit" class="btn btn-primary" style="width:100%">Sign In</button>
      </form>
    </div>`;
  document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const resp = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: document.getElementById('loginEmail').value,
          password: document.getElementById('loginPass').value,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || 'Login failed');
      token = data.access_token;
      localStorage.setItem('pot_admin_token', token);
      // Check if admin
      try {
        await api('/users');
        currentUser = { email: document.getElementById('loginEmail').value };
        render();
      } catch {
        toast('Account is not an admin', false);
        token = '';
        localStorage.removeItem('pot_admin_token');
      }
    } catch (err) {
      toast(err.message, false);
    }
  });
}

// ── Dashboard ────────────────────────────────────────────────────────────
async function renderDashboard() {
  const app = document.getElementById('app');
  app.innerHTML = `<div class="empty">Loading…</div>`;
  try {
    const [users, status] = await Promise.all([
      api('/users'),
      fetch('/api/v1/status').then(r => r.json()).catch(() => ({})),
    ]);
    renderUsers(users, status);
  } catch (err) {
    app.innerHTML = `<div class="card"><p class="empty">Error: ${esc(err.message)}</p></div>`;
  }
}

function renderUsers(users, status) {
  const app = document.getElementById('app');
  const bgutilOk = status.bgutil_available;
  const userRows = users.map(u => `
    <tr>
      <td>${esc(u.email)}${u.is_admin ? ' <span class="badge badge-admin">admin</span>' : ''}</td>
      <td><span class="badge ${u.status === 'active' ? 'badge-active' : 'badge-suspended'}">${u.status}</span></td>
      <td>${u.active_sessions}</td>
      <td>${u.has_google_credentials ? '✓' : '—'}</td>
      <td>${fmtDate(u.created_at)}</td>
      <td class="row">
        <button class="btn btn-sm btn-primary" onclick="toggleStatus('${u.id}','${u.status}')">
          ${u.status === 'active' ? 'Suspend' : 'Activate'}
        </button>
        <button class="btn btn-sm btn-danger" onclick="revokeSessions('${u.id}')">Revoke Sessions</button>
        <button class="btn btn-sm btn-primary" onclick="showKeys('${u.id}','${esc(u.email)}')">API Keys</button>
      </td>
    </tr>`).join('');

  app.innerHTML = `
    <div class="status-bar">
      <div>
        <h1>PO Token Server — Admin</h1>
        <div class="info">
          ${status.version ? 'v' + esc(status.version) + ' · ' : ''}
          bgutil: ${bgutilOk ? '<span class="badge badge-ok">online</span>' : '<span class="badge badge-revoked">offline</span>'}
          · ${users.length} user${users.length !== 1 ? 's' : ''}
        </div>
      </div>
      <button class="btn btn-sm btn-danger" onclick="logout()">Logout</button>
    </div>

    <div class="card">
      <h2>Users</h2>
      <table>
        <thead><tr><th>Email</th><th>Status</th><th>Sessions</th><th>Google</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody>${userRows || '<tr><td colspan="6" class="empty">No users</td></tr>'}</tbody>
      </table>
    </div>

    <div id="keysPanel"></div>`;
}

// ── Actions ──────────────────────────────────────────────────────────────
async function toggleStatus(userId, currentStatus) {
  const newStatus = currentStatus === 'active' ? 'suspended' : 'active';
  try {
    await api(`/users/${userId}/status`, { method: 'POST', body: JSON.stringify({ status: newStatus }) });
    toast(`User ${newStatus === 'active' ? 'activated' : 'suspended'}`);
    renderDashboard();
  } catch (err) { toast(err.message, false); }
}

async function revokeSessions(userId) {
  if (!confirm('Revoke all sessions for this user? They will need to re-login.')) return;
  try {
    const r = await api(`/users/${userId}/revoke-sessions`, { method: 'POST' });
    toast(`Revoked ${r.revoked_tokens} token(s)`);
    renderDashboard();
  } catch (err) { toast(err.message, false); }
}

async function showKeys(userId, email) {
  const panel = document.getElementById('keysPanel');
  panel.innerHTML = '<div class="card"><div class="empty">Loading…</div></div>';
  try {
    const keys = await api(`/users/${userId}/api-keys`);
    const rows = keys.map(k => `
      <tr>
        <td>${esc(k.name)}</td>
        <td>${fmtDate(k.created_at)}</td>
        <td>${fmtDate(k.last_used_at)}</td>
        <td>${k.revoked ? '<span class="badge badge-revoked">revoked</span>' : '<span class="badge badge-ok">active</span>'}</td>
        <td>${!k.revoked ? `<button class="btn btn-sm btn-danger" onclick="revokeKey('${userId}','${k.id}')">Revoke</button>` : ''}</td>
      </tr>`).join('');
    panel.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>API Keys — ${esc(email)}</h2>
          <div class="row">
            <input type="text" id="newKeyName" placeholder="Key name" style="padding:.4rem .6rem;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:.82rem;">
            <button class="btn btn-sm btn-primary" onclick="createKey('${userId}')">Create Key</button>
            <button class="btn btn-sm" onclick="document.getElementById('keysPanel').innerHTML=''">Close</button>
          </div>
        </div>
        <div id="newKeyDisplay"></div>
        <table>
          <thead><tr><th>Name</th><th>Created</th><th>Last Used</th><th>Status</th><th></th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="empty">No API keys</td></tr>'}</tbody>
        </table>
      </div>`;
  } catch (err) {
    panel.innerHTML = `<div class="card"><p class="empty">Error: ${esc(err.message)}</p></div>`;
  }
}

async function createKey(userId) {
  const name = document.getElementById('newKeyName').value || 'default';
  try {
    const r = await api(`/users/${userId}/api-keys`, { method: 'POST', body: JSON.stringify({ name }) });
    document.getElementById('newKeyDisplay').innerHTML = `
      <div class="key-display">${esc(r.api_key)}</div>
      <p style="color:var(--yellow);font-size:.78rem;margin-top:.3rem;">⚠ Store this key now — it cannot be retrieved again.</p>`;
    toast('API key created');
    showKeys(userId, document.querySelector('#keysPanel h2')?.textContent?.replace('API Keys — ', '') || '');
  } catch (err) { toast(err.message, false); }
}

async function revokeKey(userId, keyId) {
  if (!confirm('Revoke this API key?')) return;
  try {
    await api(`/users/${userId}/api-keys/${keyId}`, { method: 'DELETE' });
    toast('API key revoked');
    renderDashboard();
  } catch (err) { toast(err.message, false); }
}

function logout() {
  token = '';
  localStorage.removeItem('pot_admin_token');
  render();
}

// ── Init ─────────────────────────────────────────────────────────────────
function render() {
  if (!token) { renderLogin(); return; }
  renderDashboard();
}
render();
</script>
</body>
</html>
"""


@router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_ui(request: Request) -> HTMLResponse:
    """Serve the admin dashboard."""
    return HTMLResponse(_ADMIN_HTML)
