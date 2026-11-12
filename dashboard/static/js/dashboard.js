const API = '/api/v1';
let token = localStorage.getItem('aegis_token') || '';

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (!(options.body instanceof FormData) && options.body && typeof options.body === 'object') {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }
  const res = await fetch(API + path, { ...options, headers });
  if (res.status === 401) {
    logout();
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || res.statusText);
  }
  if (res.status === 204) return null;
  return res.json();
}

function logout() {
  token = '';
  localStorage.removeItem('aegis_token');
  $('loginPanel').classList.remove('hidden');
  $('dashboard').classList.add('hidden');
  $('logoutBtn').classList.add('hidden');
  $('userBadge').classList.add('hidden');
}

async function login(e) {
  e.preventDefault();
  $('loginError').classList.add('hidden');
  const form = new FormData();
  form.append('username', $('email').value);
  form.append('password', $('password').value);
  try {
    const data = await api('/auth/login', { method: 'POST', body: form });
    token = data.access_token;
    localStorage.setItem('aegis_token', token);
    await showDashboard();
  } catch (err) {
    $('loginError').textContent = err.message || 'ورود ناموفق';
    $('loginError').classList.remove('hidden');
  }
}

async function showDashboard() {
  $('loginPanel').classList.add('hidden');
  $('dashboard').classList.remove('hidden');
  $('logoutBtn').classList.remove('hidden');
  try {
    const me = await api('/auth/me');
    $('userBadge').textContent = me.email;
    $('userBadge').classList.remove('hidden');
  } catch {}
  await refreshAll();
}

async function refreshAll() {
  await Promise.all([loadDomains(), loadScans()]);
}

function statusBadge(status) {
  const map = {
    verified: 'bg-emerald-900/50 text-emerald-400',
    pending_verification: 'bg-amber-900/50 text-amber-400',
    disabled: 'bg-slate-700 text-slate-400',
    completed: 'bg-emerald-900/50 text-emerald-400',
    running: 'bg-blue-900/50 text-blue-400',
    failed: 'bg-red-900/50 text-red-400',
    pending: 'bg-slate-700 text-slate-300',
  };
  const labels = {
    verified: 'تأیید شده',
    pending_verification: 'در انتظار تأیید',
    disabled: 'غیرفعال',
    completed: 'تکمیل',
    running: 'در حال اجرا',
    failed: 'ناموفق',
    pending: 'در صف',
  };
  return `<span class="px-2 py-0.5 rounded text-xs ${map[status] || 'bg-slate-700'}">${labels[status] || status}</span>`;
}

function riskBadge(level) {
  const map = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-600 text-white',
    medium: 'bg-amber-600 text-white',
    low: 'bg-slate-600 text-slate-200',
    informational: 'bg-slate-700 text-slate-300',
  };
  const labels = {
    critical: 'بحرانی', high: 'بالا', medium: 'متوسط', low: 'پایین', informational: 'اطلاعاتی'
  };
  return `<span class="px-2 py-0.5 rounded text-xs ${map[level] || ''}">${labels[level] || level}</span>`;
}

async function loadDomains() {
  const list = $('domainList');
  list.innerHTML = '<p class="text-slate-500">در حال بارگذاری...</p>';
  try {
    const domains = await api('/domains');
    $('statDomains').textContent = domains.length;
    if (!domains.length) {
      list.innerHTML = '<p class="text-slate-500">هنوز دامنه‌ای ثبت نشده است.</p>';
      return;
    }
    list.innerHTML = domains.map(d => `
      <div class="flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg bg-navy-900/60 border border-navy-600">
        <div>
          <span class="font-medium">${d.display_name || d.hostname}</span>
          <span class="text-slate-500 text-xs mr-2">${d.hostname}</span>
          ${statusBadge(d.status)}
        </div>
        <div class="flex gap-2">
          ${d.status !== 'verified' ? `<button onclick="verifyDomain(${d.id})" class="px-3 py-1 rounded bg-amber-700 hover:bg-amber-600 text-xs">تأیید مالکیت</button>` : ''}
          ${d.status === 'verified' ? `<button onclick="startScan(${d.id})" class="px-3 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-xs">شروع اسکن</button>` : ''}
          <button onclick="showToken(${d.id}, '${d.verification_token}')" class="px-3 py-1 rounded bg-navy-700 hover:bg-navy-600 text-xs">توکن تأیید</button>
        </div>
      </div>
    `).join('');
  } catch (e) {
    list.innerHTML = `<p class="text-red-400">${e.message}</p>`;
  }
}

async function loadScans() {
  const list = $('scanList');
  try {
    const scans = await api('/scans');
    $('statScans').textContent = scans.length;
    let critical = 0;
    let scoreSum = 0, scoreCnt = 0;
    scans.forEach(s => {
      if (s.overall_score != null) { scoreSum += s.overall_score; scoreCnt++; }
    });
    $('statScore').textContent = scoreCnt ? (scoreSum / scoreCnt).toFixed(1) : '—';
    // critical count would need full findings; approximate from summary later
    if (!scans.length) {
      list.innerHTML = '<p class="text-slate-500">اسکنی ثبت نشده است.</p>';
      return;
    }
    list.innerHTML = `
      <table class="w-full text-right">
        <thead class="text-slate-400 border-b border-navy-600">
          <tr>
            <th class="py-2 px-2">شناسه</th>
            <th class="py-2 px-2">دامنه</th>
            <th class="py-2 px-2">وضعیت</th>
            <th class="py-2 px-2">امتیاز</th>
            <th class="py-2 px-2">یافته‌ها</th>
            <th class="py-2 px-2">زمان</th>
            <th class="py-2 px-2"></th>
          </tr>
        </thead>
        <tbody>
          ${scans.map(s => `
            <tr class="border-b border-navy-700/50 hover:bg-navy-800/50">
              <td class="py-2 px-2">#${s.id}</td>
              <td class="py-2 px-2">${s.domain_id}</td>
              <td class="py-2 px-2">${statusBadge(s.status)}</td>
              <td class="py-2 px-2 font-mono">${s.overall_score != null ? s.overall_score : '—'}</td>
              <td class="py-2 px-2">${s.findings_count}</td>
              <td class="py-2 px-2 text-slate-400 text-xs">${s.finished_at ? new Date(s.finished_at).toLocaleString('fa-IR') : '—'}</td>
              <td class="py-2 px-2"><button onclick="showFindings(${s.id})" class="text-emerald-400 hover:underline text-xs">جزئیات</button></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (e) {
    list.innerHTML = `<p class="text-red-400">${e.message}</p>`;
  }
}

async function verifyDomain(id) {
  try {
    const res = await api(`/domains/${id}/verify`, { method: 'POST' });
    alert(res.message);
    await loadDomains();
  } catch (e) {
    alert(e.message);
  }
}

function showToken(id, token) {
  alert(`توکن تأیید دامنه:\n\n${token}\n\nاین مقدار را در رکورد TXT دامنه یا فایل /.well-known/aegis-sentinel-verification.txt قرار دهید.`);
}

async function startScan(domainId) {
  if (!confirm('اسکن غیرتخریبی برای این دامنه شروع شود؟')) return;
  try {
    const scan = await api('/scans', {
      method: 'POST',
      body: { domain_id: domainId },
    });
    alert(`اسکن #${scan.id} تکمیل شد. امتیاز: ${scan.overall_score}`);
    await refreshAll();
    showFindings(scan.id);
  } catch (e) {
    alert('خطا: ' + e.message);
  }
}

async function showFindings(scanId) {
  const panel = $('findingsPanel');
  const list = $('findingsList');
  panel.classList.remove('hidden');
  list.innerHTML = 'در حال بارگذاری...';
  try {
    const scan = await api(`/scans/${scanId}`);
    let crit = 0;
    list.innerHTML = (scan.findings || []).map(f => {
      if (f.risk_level === 'critical' || f.risk_level === 'high') crit++;
      return `
        <div class="p-3 rounded-lg bg-navy-900/70 border border-navy-600">
          <div class="flex flex-wrap items-center gap-2 mb-1">
            ${riskBadge(f.risk_level)}
            <span class="font-medium">${f.title}</span>
            <span class="text-xs text-slate-500">${f.check_name}</span>
          </div>
          <p class="text-sm text-slate-300 mb-1">${f.description}</p>
          ${f.affected_url ? `<p class="text-xs text-slate-500 dir-ltr text-left">${f.affected_url}</p>` : ''}
          ${f.remediation ? `<p class="text-xs text-emerald-400/90 mt-1">راهکار: ${f.remediation}</p>` : ''}
        </div>
      `;
    }).join('') || '<p class="text-slate-500">یافته‌ای ثبت نشده.</p>';
    $('statCritical').textContent = crit;
  } catch (e) {
    list.innerHTML = `<p class="text-red-400">${e.message}</p>`;
  }
}

// Events
$('loginForm').addEventListener('submit', login);
$('logoutBtn').addEventListener('click', logout);
$('btnAddDomain').addEventListener('click', () => {
  $('modalAdd').classList.remove('hidden');
  $('modalAdd').classList.add('flex');
});
$('cancelAdd').addEventListener('click', () => {
  $('modalAdd').classList.add('hidden');
  $('modalAdd').classList.remove('flex');
});
$('addDomainForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/domains', {
      method: 'POST',
      body: {
        hostname: $('newHostname').value.trim(),
        display_name: $('newDisplay').value.trim() || null,
      },
    });
    $('modalAdd').classList.add('hidden');
    $('modalAdd').classList.remove('flex');
    $('newHostname').value = '';
    $('newDisplay').value = '';
    await loadDomains();
  } catch (err) {
    alert(err.message);
  }
});

// Auto login if token
if (token) {
  showDashboard().catch(logout);
}
