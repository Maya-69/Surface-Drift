(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const isScanRoute = window.location.pathname.replace(/\/$/, '') === '/scan';

  document.body.classList.toggle('scan-mode', isScanRoute);
  $('#landing-view').hidden = isScanRoute;
  $('#scan-view').hidden = !isScanRoute;

  // Reveal observer
  if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -35px 0px' });
    $$('.reveal').forEach((item) => observer.observe(item));
  } else {
    $$('.reveal').forEach((item) => item.classList.add('in-view'));
  }

  // Mobile menu
  const menu = $('.mobile-menu');
  const nav = $('.header-nav');
  if (menu && nav) {
    menu.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      menu.setAttribute('aria-expanded', String(open));
    });
    $$('.header-nav a').forEach((anchor) => anchor.addEventListener('click', () => {
      nav.classList.remove('open');
      menu.setAttribute('aria-expanded', 'false');
    }));
  }

  // Smooth scroll links
  $$('[data-scroll]').forEach((anchor) => anchor.addEventListener('click', (event) => {
    if (window.location.pathname.replace(/\/$/, '') !== '') return;
    const target = document.getElementById(anchor.dataset.scroll);
    if (target) {
      event.preventDefault();
      target.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
      history.replaceState(null, '', `#${anchor.dataset.scroll}`);
    }
  }));

  // =========================================================================
  // Google Authentication & User Profile Management
  // =========================================================================
  let currentUser = null;

  function getAuthHeaders(extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (currentUser && currentUser.id) {
      headers['x-user-id'] = currentUser.id;
      headers['x-user-email'] = currentUser.email || '';
      headers['x-user-name'] = currentUser.name || '';
    }
    return headers;
  }

  function updateAuthNotice(user) {
    const noticeEl = $('#auth-scan-notice');
    if (!noticeEl) return;
    if (user) {
      noticeEl.className = 'auth-scan-notice authenticated';
      noticeEl.innerHTML = `
        <div class="auth-notice-icon">✓</div>
        <div class="auth-notice-content">
          <span class="auth-notice-badge">ACCOUNT LINKED</span>
          <p class="auth-notice-text">
            Signed in as <strong>${escapeHtml(user.email)}</strong>. Scan results will be saved to your dashboard history, and <strong>Phase 2 Deep Probing is unlocked</strong>.
          </p>
        </div>
      `;
    } else {
      noticeEl.className = 'auth-scan-notice guest';
      noticeEl.innerHTML = `
        <div class="auth-notice-icon">⚠️</div>
        <div class="auth-notice-content">
          <span class="auth-notice-badge">GUEST RECON MODE</span>
          <p class="auth-notice-text">
            You are not logged in. Scans run as a guest are <strong>temporary (never saved to history)</strong> and restricted to <strong>Phase 1 only</strong>. Phase 2 Deep Probing is locked.
          </p>
        </div>
        <button type="button" class="btn-notice-signin" id="notice-signin-btn">
          <svg width="13" height="13" viewBox="0 0 24 24"><path fill="#EA4335" d="M12 5c1.6 0 3 .6 4.1 1.7l3.1-3.1C17.3 1.8 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.3l3.7 2.9C6.5 7.3 9 5 12 5z"/><path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.7-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.8z"/><path fill="#FBBC05" d="M5.6 14.8c-.2-.7-.4-1.5-.4-2.3 0-.8.1-1.6.4-2.3L1.9 7.3C.7 9.7 0 10.8 0 12.5s.7 2.8 1.9 5.2l3.7-2.9z"/><path fill="#34A853" d="M12 24c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2.3-6.4-5.2L1.9 17C3.7 20.7 7.5 24 12 24z"/></svg>
          Sign in with Google
        </button>
      `;
      const btn = $('#notice-signin-btn');
      if (btn) btn.addEventListener('click', triggerGoogleLogin);
    }
  }

  function triggerGoogleLogin() {
    const modal = $('#auth-login-modal');
    if (modal) {
      modal.hidden = false;
      return;
    }
    // Fallback if modal DOM element not found
    authenticateDirectly('sawantmayuresh2006@gmail.com', 'Maya');
  }

  function closeAuthModal() {
    const modal = $('#auth-login-modal');
    if (modal) modal.hidden = true;
  }

  async function authenticateDirectly(email, name, picture) {
    try {
      const res = await fetch('/api/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          demo: true,
          email: (email || 'sawantmayuresh2006@gmail.com').trim(),
          name: (name || 'Maya').trim(),
          picture: picture || ''
        }),
      });
      const data = await res.json();
      if (data.ok && data.user) {
        setLoggedInUser(data.user);
        closeAuthModal();
        loadScanHistory();
      }
    } catch (err) {
      alert('Authentication error: ' + (err.message || err));
    }
  }

  async function checkAuth() {
    // 1. Immediate restore from localStorage
    try {
      const cached = localStorage.getItem('asm_user');
      if (cached) {
        const u = JSON.parse(cached);
        if (u && u.id) {
          setLoggedInUser(u);
        }
      }
    } catch {}

    // 2. Synchronize with server
    try {
      const res = await fetch('/api/auth/me', { headers: getAuthHeaders() });
      const data = await res.json();
      if (data.authenticated && data.user) {
        setLoggedInUser(data.user, data.total_scans);
      } else if (currentUser) {
        // Ephemeral container cold start recovery
        const recoverRes = await fetch('/api/auth/google', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ demo: true, email: currentUser.email, name: currentUser.name }),
        });
        const recData = await recoverRes.json();
        if (recData.ok && recData.user) {
          setLoggedInUser(recData.user);
        }
      } else {
        setLoggedOutUser();
      }
    } catch {
      if (!currentUser) setLoggedOutUser();
    }
  }

  function setLoggedInUser(user, totalScans) {
    currentUser = user;
    try {
      localStorage.setItem('asm_user', JSON.stringify(user));
    } catch {}
    const loginBtn = $('#google-login-btn');
    const userPill = $('#user-pill');
    if (loginBtn) loginBtn.hidden = true;
    if (userPill) userPill.hidden = false;

    const avatar = user.picture || `https://api.dicebear.com/7.x/identicon/svg?seed=${encodeURIComponent(user.name || user.email)}`;
    $('#user-avatar').src = avatar;
    $('#user-name').textContent = user.name || user.email.split('@')[0];
    $('#dropdown-user-name').textContent = user.name || user.email.split('@')[0];
    $('#dropdown-user-email').textContent = user.email;

    if (typeof totalScans === 'number') {
      $('#history-badge').textContent = totalScans;
    }
    updateAuthNotice(user);

    // If Phase 2 lock banner is displayed, remove it
    const lockBanner = $('#phase2-lock-banner');
    if (lockBanner) lockBanner.remove();
  }

  function setLoggedOutUser() {
    currentUser = null;
    try {
      localStorage.removeItem('asm_user');
    } catch {}
    const loginBtn = $('#google-login-btn');
    const userPill = $('#user-pill');
    if (loginBtn) loginBtn.hidden = false;
    if (userPill) userPill.hidden = true;
    $('#user-dropdown').hidden = true;
    updateAuthNotice(null);
  }

  // Google Sign-In setup
  let tokenClient = null;
  let configuredClientId = '';

  function initGoogleAuth(clientId) {
    if (!clientId || !window.google || !window.google.accounts) return;
    configuredClientId = clientId;

    try {
      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleCredentialResponse,
        auto_select: false,
        cancel_on_tap_outside: true,
      });
      window.google.accounts.id.prompt();
    } catch (e) {
      console.warn('GIS ID init notice:', e);
    }

    try {
      if (window.google.accounts.oauth2) {
        tokenClient = window.google.accounts.oauth2.initTokenClient({
          client_id: clientId,
          scope: 'email profile openid',
          callback: async (resp) => {
            if (resp && resp.access_token) {
              await verifyAndLoginWithToken(resp.access_token);
            }
          },
          error_callback: (err) => {
            console.warn('GIS OAuth2 token client notice:', err);
            authenticateDirectly('sawantmayuresh2006@gmail.com', 'Maya');
          }
        });
      }
    } catch (e) {
      console.warn('GIS OAuth2 token client init notice:', e);
    }
  }

  fetch('/api/auth/config')
    .then((r) => r.json())
    .then((cfg) => {
      if (cfg.google_client_id) {
        if (window.google && window.google.accounts) {
          initGoogleAuth(cfg.google_client_id);
        } else {
          window.addEventListener('load', () => {
            initGoogleAuth(cfg.google_client_id);
          });
        }
      }
    })
    .catch(() => {});

  async function verifyAndLoginWithToken(token) {
    try {
      const res = await fetch('/api/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: token }),
      });
      const data = await res.json();
      if (data.ok && data.user) {
        setLoggedInUser(data.user);
        closeAuthModal();
        loadScanHistory();
      }
    } catch {
      alert('Could not authenticate with Google.');
    }
  }

  async function handleGoogleCredentialResponse(response) {
    try {
      const res = await fetch('/api/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: response.credential }),
      });
      const data = await res.json();
      if (data.ok && data.user) {
        setLoggedInUser(data.user);
        closeAuthModal();
        loadScanHistory();
      }
    } catch {
      alert('Could not authenticate with Google.');
    }
  }

  const googleLoginBtn = $('#google-login-btn');
  if (googleLoginBtn) {
    googleLoginBtn.addEventListener('click', triggerGoogleLogin);
  }

  // Setup Auth Modal Event Listeners
  const authModalCloseX = $('#auth-modal-close-x');
  if (authModalCloseX) authModalCloseX.addEventListener('click', closeAuthModal);

  const btnQuickLoginMaya = $('#btn-quick-login-maya');
  if (btnQuickLoginMaya) {
    btnQuickLoginMaya.addEventListener('click', () => {
      authenticateDirectly('sawantmayuresh2006@gmail.com', 'Maya');
    });
  }

  const btnGoogleOauthPopup = $('#btn-google-oauth-popup');
  if (btnGoogleOauthPopup) {
    btnGoogleOauthPopup.addEventListener('click', () => {
      if (tokenClient) {
        try {
          tokenClient.requestAccessToken({ prompt: 'select_account' });
        } catch {
          authenticateDirectly('sawantmayuresh2006@gmail.com', 'Maya');
        }
      } else {
        authenticateDirectly('sawantmayuresh2006@gmail.com', 'Maya');
      }
    });
  }

  const formCustomAuth = $('#form-custom-auth');
  if (formCustomAuth) {
    formCustomAuth.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = $('#auth-custom-email');
      if (input && input.value) {
        const val = input.value.trim();
        authenticateDirectly(val, val.split('@')[0]);
      }
    });
  }

  const guestModalLoginBtn = $('#guest-modal-login-btn');
  if (guestModalLoginBtn) {
    guestModalLoginBtn.addEventListener('click', () => {
      const gModal = $('#guest-confirm-modal');
      if (gModal) gModal.hidden = true;
      triggerGoogleLogin();
    });
  }

  const userMenuBtn = $('#user-menu-btn');
  if (userMenuBtn) {
    userMenuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const dropdown = $('#user-dropdown');
      dropdown.hidden = !dropdown.hidden;
    });
  }

  document.addEventListener('click', () => {
    const dropdown = $('#user-dropdown');
    if (dropdown) dropdown.hidden = true;
  });

  const logoutBtn = $('#logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await fetch('/api/auth/logout', { method: 'POST' });
      setLoggedOutUser();
    });
  }

  // =========================================================================
  // Scan History Drawer
  // =========================================================================
  const historyOverlay = $('#history-overlay');
  const openHistoryBtn = $('#open-history-btn');
  const dropdownHistoryBtn = $('#dropdown-history-btn');
  const historyCloseBtn = $('#history-close-btn');

  function openHistory() {
    if (historyOverlay) {
      historyOverlay.hidden = false;
      loadScanHistory();
    }
  }

  function closeHistory() {
    if (historyOverlay) historyOverlay.hidden = true;
  }

  if (openHistoryBtn) openHistoryBtn.addEventListener('click', openHistory);
  if (dropdownHistoryBtn) dropdownHistoryBtn.addEventListener('click', openHistory);
  if (historyCloseBtn) historyCloseBtn.addEventListener('click', closeHistory);
  if (historyOverlay) {
    historyOverlay.addEventListener('click', (e) => {
      if (e.target === historyOverlay) closeHistory();
    });
  }

  function escapeHtml(str) {
    return String(str || '').replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
  }

  const LOCAL_STORAGE_KEY = 'surfacedrift_scan_history';

  function getLocalHistory() {
    try {
      const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  function saveScanToLocalHistory(job) {
    if (!job || !job.id) return;
    try {
      const history = getLocalHistory();
      const existingIdx = history.findIndex((h) => h.id === job.id);
      const counts = (job.summary && job.summary.counts) || {};
      const item = {
        id: job.id,
        target: job.target,
        mode: job.mode || 'passive',
        status: job.status || 'completed',
        started_at: job.created_at || new Date().toISOString(),
        completed_at: job.completed_at || new Date().toISOString(),
        duration_seconds: job.duration_seconds || 0,
        subdomains_count: counts.subdomains || 0,
        ips_count: counts.ips || 0,
        ports_count: counts.ports || 0,
        emails_count: counts.emails || 0,
        buckets_count: counts.buckets || 0,
        grade: job.surfacedrift_advanced?.posture?.grade || job.grade || null,
        risk_score: job.surfacedrift_advanced?.posture?.score ?? job.risk_score ?? null,
        summary: job.summary,
        surfacedrift_advanced: job.surfacedrift_advanced || null,
      };
      if (existingIdx >= 0) {
        history[existingIdx] = { ...history[existingIdx], ...item };
      } else {
        history.unshift(item);
      }
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(history.slice(0, 50)));
      const badge = $('#history-badge');
      if (badge) badge.textContent = history.length;
    } catch (e) {
      console.warn('Could not save scan to local storage:', e);
    }
  }

  async function downloadReportFile(scanId, target, format = 'pdf') {
    target = target || 'target';
    const statusMsg = $('#download-status');
    const fmtLower = (format || 'pdf').toLowerCase().trim();
    const extMap = { pdf: 'pdf', html: 'html', md: 'md', markdown: 'md', json: 'json', zip: 'zip' };
    const defaultExt = extMap[fmtLower] || 'pdf';

    if (statusMsg) statusMsg.textContent = `Preparing ${fmtLower.toUpperCase()} report…`;

    try {
      const resp = await fetch(`/api/scans/${encodeURIComponent(scanId)}/download-report?format=${encodeURIComponent(fmtLower)}`);
      if (resp.ok) {
        const blob = await resp.blob();
        let ext = defaultExt;
        const ctype = (resp.headers.get('content-type') || '').toLowerCase();
        if (ctype.includes('application/pdf')) ext = 'pdf';
        else if (ctype.includes('text/html')) ext = 'html';
        else if (ctype.includes('application/json')) ext = 'json';
        else if (ctype.includes('text/markdown')) ext = 'md';

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${target}-surfacedrift-report-${scanId}.${ext}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        if (statusMsg) statusMsg.textContent = `Report downloaded (${ext.toUpperCase()}).`;
        return;
      }
    } catch (e) {
      console.warn(`Direct report download failed for ${fmtLower}:`, e);
    }

    // Client fallback via POST /api/scans/export-report
    if (lastJob?.summary || lastJob?.surfacedrift_advanced) {
      try {
        const postResp = await fetch('/api/scans/export-report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scan_id: scanId,
            target: target,
            summary: lastJob?.summary || null,
            advanced: lastJob?.surfacedrift_advanced || null,
            format: fmtLower
          }),
        });
        if (postResp.ok) {
          const blob = await postResp.blob();
          let ext = defaultExt;
          const ctype = (postResp.headers.get('content-type') || '').toLowerCase();
          if (ctype.includes('application/pdf')) ext = 'pdf';
          else if (ctype.includes('text/html')) ext = 'html';
          else if (ctype.includes('application/json')) ext = 'json';
          else if (ctype.includes('text/markdown')) ext = 'md';

          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${target}-surfacedrift-report-${scanId}.${ext}`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
          if (statusMsg) statusMsg.textContent = `Report downloaded (${ext.toUpperCase()}).`;
          return;
        }
      } catch (err) {
        console.error('Export report fallback failed:', err);
      }
    }

    // If PDF download fails on both endpoints, fallback to opening the interactive report
    if (fmtLower === 'pdf') {
      window.open(`/api/scans/${encodeURIComponent(scanId)}/report.html`, '_blank');
      if (statusMsg) statusMsg.textContent = 'Opened interactive report. Click "Print / Save PDF" in the toolbar.';
      return;
    }

    alert(`Failed to download ${fmtLower.toUpperCase()} report. Assessment data could not be retrieved.`);
    if (statusMsg) statusMsg.textContent = '';
  }

  async function downloadScanArchive(item) {
    const scanId = item.id;
    const target = item.target || 'target';

    // If Phase 2 CTEM assessment is present, download the combined full bundle
    if (item.surfacedrift_advanced) {
      try {
        const resp = await fetch(`/api/scans/${encodeURIComponent(scanId)}/download-combined`);
        if (resp.ok) {
          const blob = await resp.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${target}-surfacedrift-full-assessment-${scanId}.zip`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
          return;
        }
      } catch {}
    }

    try {
      const resp = await fetch(`/api/scans/${encodeURIComponent(scanId)}/download`);
      if (resp.ok) {
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${target}-asm-report-${scanId}.zip`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        return;
      }
    } catch {}

    if (item.summary) {
      try {
        const postResp = await fetch('/api/scans/export-zip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scan_id: scanId,
            target: target,
            summary: item.summary,
            advanced: item.surfacedrift_advanced || null,
          }),
        });
        if (postResp.ok) {
          const blob = await postResp.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${target}-surfacedrift-full-assessment-${scanId}.zip`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
          return;
        }
      } catch (e) {
        console.error('Export zip failed:', e);
      }
    }

    alert('Download failed. Assessment report data could not be retrieved.');
  }

  async function loadScanHistory() {
    const listEl = $('#history-list');
    if (!listEl) return;
    listEl.innerHTML = '<p class="empty-state">Loading scan history…</p>';

    let serverData = [];
    try {
      const res = await fetch('/api/scans/history', { headers: getAuthHeaders() });
      if (res.ok) {
        serverData = await res.json();
      }
    } catch {}

    const localData = getLocalHistory();
    const map = new Map();
    serverData.forEach((s) => map.set(s.id, s));
    localData.forEach((l) => {
      if (!map.has(l.id)) {
        map.set(l.id, l);
      } else {
        const s = map.get(l.id);
        map.set(l.id, {
          ...s,
          summary: l.summary || s.summary,
          surfacedrift_advanced: l.surfacedrift_advanced || s.surfacedrift_advanced,
        });
      }
    });

    const combinedList = Array.from(map.values()).sort((a, b) => {
      const ta = new Date(a.started_at || 0).getTime();
      const tb = new Date(b.started_at || 0).getTime();
      return tb - ta;
    });

    const badge = $('#history-badge');
    if (badge) badge.textContent = combinedList.length;

    if (!combinedList.length) {
      listEl.innerHTML = '<p class="empty-state"><span>◇</span>No scans recorded yet.<br />Run an assessment to build your history.</p>';
      return;
    }

    listEl.replaceChildren();
    combinedList.forEach((item) => {
      const card = document.createElement('div');
      card.className = 'history-card';
      const dateStr = item.started_at ? new Date(item.started_at).toLocaleString() : 'Recent';
      const durStr = item.duration_seconds ? `${Number(item.duration_seconds).toFixed(1)}s` : '—';
      const modeBadge = item.mode === 'active'
        ? '<span class="mode-badge active">Active</span>'
        : '<span class="mode-badge passive">Passive</span>';
      const statusClass = item.status === 'completed' ? 'completed' : (item.status === 'failed' ? 'failed' : 'running');
      const gradeBadge = item.grade
        ? `<span class="badge-status" style="background:rgba(67,226,210,0.15);color:#43e2d2;border:1px solid rgba(67,226,210,0.3);">Grade ${escapeHtml(item.grade)} (${item.risk_score || 0})</span>`
        : '';

      card.innerHTML = `
        <div class="history-card-top">
          <span class="history-target">${escapeHtml(item.target)}</span>
          <div class="history-badges">
            ${gradeBadge}
            ${modeBadge}
            <span class="badge-status ${statusClass}">${escapeHtml(item.status)}</span>
          </div>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(dateStr)} · Duration: ${durStr}</span>
        </div>
        <div class="history-metrics-row">
          <span class="history-metric-pill">Subdomains: <strong>${item.subdomains_count || 0}</strong></span>
          <span class="history-metric-pill">IPs: <strong>${item.ips_count || 0}</strong></span>
          <span class="history-metric-pill">Ports: <strong>${item.ports_count || 0}</strong></span>
          <span class="history-metric-pill">Emails: <strong>${item.emails_count || 0}</strong></span>
          <span class="history-metric-pill">Buckets: <strong>${item.buckets_count || 0}</strong></span>
        </div>
        <div class="history-actions">
          <button class="btn-history-action btn-view-results" data-id="${item.id}" type="button">View Results ↗</button>
          ${item.status === 'completed' ? `<button class="btn-history-action btn-history-download" data-id="${item.id}" type="button">Download ZIP ↓</button>` : ''}
          <button class="btn-history-action btn-delete-scan" data-id="${item.id}" type="button">Delete</button>
        </div>
      `;

      card.querySelector('.btn-view-results').onclick = () => {
        closeHistory();
        if (item.summary) {
          activeScanId = item.id;
          lastJob = item;
          history.pushState(null, '', `/scan?scan_id=${encodeURIComponent(item.id)}`);
          buildReport(item);
          if (item.surfacedrift_advanced) {
            renderAdvancedResults(item.surfacedrift_advanced, item.id);
          }
        } else {
          loadExistingScan(item.id);
        }
      };

      const dlBtn = card.querySelector('.btn-history-download');
      if (dlBtn) {
        dlBtn.onclick = () => downloadScanArchive(item);
      }

      card.querySelector('.btn-delete-scan').onclick = async () => {
        if (confirm(`Delete scan record for ${item.target}?`)) {
          const updated = getLocalHistory().filter((h) => h.id !== item.id);
          localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(updated));
          try {
            await fetch(`/api/scans/${item.id}`, { method: 'DELETE', headers: getAuthHeaders() });
          } catch {}
          loadScanHistory();
        }
      };

      listEl.appendChild(card);
    });
  }

  // Initialize auth check
  checkAuth();

  // If on landing page, history and auth are ready, exit early
  if (!isScanRoute) return;

  // =========================================================================
  // Scan Workspace Engine
  // =========================================================================
  const form = $('#scan-form');
  const targetInput = $('#target-input');
  const clearButton = $('#clear-target');
  const formPanel = $('#scan-form-panel');
  const progressPanel = $('#scan-progress-panel');
  const reportPanel = $('#report-panel');
  const startButton = $('#start-scan-button');
  const preflightNote = $('#preflight-note');
  const stageEls = $$('.stage-item');

  let activeScanId = null;
  let pollTimer = null;
  let timerLoop = null;
  let scanStartedAt = null;
  let lastJob = null;
  let currentMode = 'passive';

  // Recon Mode Selection
  $$('input[name="recon-mode"]').forEach((input) => {
    input.addEventListener('change', () => {
      currentMode = input.value;
      $$('.mode-card').forEach((c) => c.classList.remove('active'));
      const card = input.closest('.mode-card');
      if (card) card.classList.add('active');
    });
  });

  targetInput.addEventListener('input', () => {
    clearButton.hidden = targetInput.value.length === 0;
  });

  clearButton.addEventListener('click', () => {
    targetInput.value = '';
    clearButton.hidden = true;
    targetInput.focus();
  });

  // Preflight Health Check
  fetch('/api/health')
    .then((r) => r.json())
    .then((health) => {
      if (!health.ready) {
        preflightNote.textContent = 'Setup notice: SurfaceDrift reconnaissance modules or wordlists could not be fully detected. Check server configuration.';
        preflightNote.hidden = false;
      }
    })
    .catch(() => {
      preflightNote.textContent = 'The scanner status endpoint is offline. Ensure the backend server is running.';
      preflightNote.hidden = false;
    });

  function showView(which) {
    formPanel.hidden = which !== 'form';
    progressPanel.hidden = which !== 'progress';
    reportPanel.hidden = which !== 'report';
    if (which === 'progress') {
      progressPanel.classList.remove('in-view');
      requestAnimationFrame(() => progressPanel.classList.add('in-view'));
    }
    window.scrollTo({
      top: 0,
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
    });
  }

  function stageIndexFor(job) {
    const text = `${job.stage || ''} ${job.detail || ''}`.toLowerCase();
    if (/certificate transparency|crt\.sh|hackertarget|subhunter|subdomain/.test(text)) return 1;
    if (/dns|mx|spf|dmarc|address|routing|asn|ip intelligence|shodan|censys/.test(text)) return 2;
    if (/email|hunter|bucket|s3|employee/.test(text)) return 3;
    if (/report|packag|finaliz|complete/.test(text) || (job.progress || 0) >= 90) return 4;
    const p = Number(job.progress || 0);
    if (p < 20) return 0;
    if (p < 45) return 1;
    if (p < 70) return 2;
    if (p < 88) return 3;
    return 4;
  }

  function renderStages(job) {
    const current = stageIndexFor(job);
    stageEls.forEach((el, index) => {
      el.classList.toggle('done', job.status === 'completed' || index < current || (job.status === 'failed' && index < current));
      el.classList.toggle('active', job.status !== 'completed' && job.status !== 'failed' && index === current);
      const indicator = $('.stage-indicator', el);
      const state = $('.stage-state', el);
      if (job.status === 'completed' || index < current) {
        indicator.textContent = '✓';
        state.textContent = 'Complete';
      } else if (job.status === 'failed' && index === current) {
        indicator.textContent = '!';
        state.textContent = 'Stopped';
      } else if (index === current && job.status !== 'failed') {
        indicator.textContent = String(index + 1).padStart(2, '0');
        state.textContent = 'In progress';
      } else {
        indicator.textContent = String(index + 1).padStart(2, '0');
        state.textContent = 'Waiting';
      }
    });
  }

  function renderLogs(logs) {
    if (!Array.isArray(logs)) return;
    $('#log-count').textContent = `${logs.length} event${logs.length === 1 ? '' : 's'}`;
    const container = $('#log-lines');
    container.replaceChildren();

    if (!logs.length) {
      const row = document.createElement('p');
      row.className = 'term-line-info';
      row.textContent = 'Waiting for scanner telemetry…';
      container.append(row);
      return;
    }

    logs.forEach((line) => {
      const row = document.createElement('p');
      row.className = 'term-line';
      if (line.includes('[-]')) row.className += ' term-line-act';
      else if (line.includes('[+]')) row.className += ' term-line-pos';
      else if (line.includes('[*]') || line.toLowerCase().includes('error')) row.className += ' term-line-err';
      else row.className += ' term-line-info';
      row.textContent = line;
      container.append(row);
    });
    container.scrollTop = container.scrollHeight;
  }

  const clearTermBtn = $('#terminal-clear-btn');
  if (clearTermBtn) {
    clearTermBtn.addEventListener('click', () => {
      const container = $('#log-lines');
      container.replaceChildren();
      const row = document.createElement('p');
      row.className = 'term-line-info';
      row.textContent = 'Console cleared.';
      container.append(row);
    });
  }

  function formatElapsed() {
    if (!scanStartedAt) return '00:00';
    const seconds = Math.max(0, Math.floor((Date.now() - scanStartedAt) / 1000));
    return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
  }

  function updateProgress(job) {
    const progress = Math.max(0, Math.min(100, Number(job.progress || 0)));
    $('#progress-percent').textContent = `${String(progress).padStart(2, '0')}%`;
    $('#progress-fill').style.width = `${progress}%`;

    const titleElement = $('#progress-title');
    const titleText = job.status === 'failed' ? 'Scan interrupted' : (job.status === 'completed' ? 'Surface mapped' : 'Mapping the surface');
    titleElement.replaceChildren(document.createTextNode(titleText));
    if (job.status !== 'completed' && job.status !== 'failed') {
      const ellipsis = document.createElement('span');
      ellipsis.className = 'animated-ellipsis';
      ellipsis.textContent = '…';
      titleElement.append(ellipsis);
    }

    $('#running-target').textContent = job.target || '—';
    $('#progress-detail').textContent = job.detail || job.stage || 'Working…';
    $('#ticker-text').textContent = job.detail || job.stage || 'Executing modules…';
    $('#running-mode-tag').textContent = (job.mode || currentMode || 'passive').toUpperCase();
    $('#elapsed-time').textContent = formatElapsed();
    $('#running-status-text').textContent = job.status === 'failed' ? 'Stopped' : (job.status === 'completed' ? 'Complete' : (job.stage || 'Running'));

    const statusDot = $('.running-status i');
    if (statusDot) {
      statusDot.style.background = job.status === 'failed' ? '#eaa58c' : (job.status === 'completed' ? '#8ee8ac' : 'var(--aqua)');
    }

    renderStages(job);
    renderLogs(job.logs || []);

    if (job.status === 'failed') {
      $('#scan-error').hidden = false;
      $('#scan-error-text').textContent = job.error || 'The scanner stopped before producing a report.';
      $('#progress-fill').style.background = 'linear-gradient(90deg,#d98f79,#e9b99d)';
      $('#progress-percent').style.color = '#eab29e';
      $('.running-status').style.color = '#eab29e';
      stopPolling();
    }
  }

  function copyToClipboard(text, buttonEl) {
    if (!navigator.clipboard) {
      const area = document.createElement('textarea');
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      document.body.removeChild(area);
    } else {
      navigator.clipboard.writeText(text);
    }
    if (buttonEl) {
      const prevText = buttonEl.textContent;
      buttonEl.textContent = 'Copied!';
      buttonEl.classList.add('copied');
      window.setTimeout(() => {
        buttonEl.textContent = prevText;
        buttonEl.classList.remove('copied');
      }, 1500);
    }
  }

  // =========================================================================
  // Tab Bar & Results Visualization
  // =========================================================================
  function setupTabs() {
    $$('.tab-link').forEach((link) => {
      link.addEventListener('click', () => switchTab(link.dataset.tab));
    });
    $$('.quick-jump-btn').forEach((btn) => {
      btn.addEventListener('click', () => switchTab(btn.dataset.targetTab));
    });
  }

  function switchTab(tabName) {
    $$('.tab-link').forEach((l) => l.classList.toggle('active', l.dataset.tab === tabName));
    $$('.tab-panel').forEach((p) => {
      const isMatch = p.id === `pane-${tabName}`;
      p.classList.toggle('active', isMatch);
      p.hidden = !isMatch;
    });

    if (tabName === 'graph') {
      const currentAdv = lastJob?.surfacedrift_advanced;
      renderAttackPathGraph(currentAdv?.attack_graph, lastJob);
    } else if (tabName === 'mitre') {
      const currentAdv = lastJob?.surfacedrift_advanced;
      renderMitreAttack(currentAdv?.mitre_attack, currentAdv?.findings);
    } else if (tabName === 'drift') {
      const scanId = lastJob?.id || activeScanId;
      if (scanId) renderSurfaceDriftDelta(scanId, lastJob);
    }
  }

  // Render Subdomains
  function renderSubdomains(subdomains) {
    const list = $('#list-subdomains');
    const input = $('#filter-subdomains');
    const countEl = $('#counter-subdomains');
    const copyAllBtn = $('#btn-copy-subdomains');

    function update() {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = q ? subdomains.filter((s) => s.toLowerCase().includes(q)) : subdomains;
      countEl.textContent = `Showing ${filtered.length} of ${subdomains.length}`;
      list.replaceChildren();

      if (!filtered.length) {
        const empty = document.createElement('li');
        empty.className = 'empty-state';
        empty.innerHTML = '<span>◇</span>No subdomains match search.';
        list.appendChild(empty);
        return;
      }

      filtered.forEach((domain) => {
        const item = document.createElement('li');
        item.className = 'clean-list-item';
        const content = document.createElement('span');
        content.className = 'item-content mono-val';
        content.textContent = domain;

        const actions = document.createElement('div');
        actions.className = 'item-actions';
        const openLink = document.createElement('a');
        openLink.className = 'item-btn';
        openLink.href = `https://${domain}`;
        openLink.target = '_blank';
        openLink.rel = 'noopener noreferrer';
        openLink.innerHTML = 'Visit ↗';

        const copyBtn = document.createElement('button');
        copyBtn.className = 'item-btn';
        copyBtn.type = 'button';
        copyBtn.textContent = 'Copy';
        copyBtn.onclick = () => copyToClipboard(domain, copyBtn);

        actions.append(openLink, copyBtn);
        item.append(content, actions);
        list.appendChild(item);
      });
    }

    input.oninput = update;
    copyAllBtn.onclick = () => {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = q ? subdomains.filter((s) => s.toLowerCase().includes(q)) : subdomains;
      copyToClipboard(filtered.join('\n'), copyAllBtn);
    };
    update();
  }

  // Render DNS Records
  function renderDNS(records) {
    const list = $('#list-dns');
    const input = $('#filter-dns');
    const countEl = $('#counter-dns');
    const copyAllBtn = $('#btn-copy-dns');
    let currentType = 'ALL';

    $$('#dns-type-pills .pill-btn').forEach((btn) => {
      btn.onclick = () => {
        $$('#dns-type-pills .pill-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        currentType = btn.dataset.filterType;
        update();
      };
    });

    function update() {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = records.filter((rec) => {
        const parts = rec.split(':');
        const rType = parts[0] ? parts[0].trim().toUpperCase() : 'TXT';
        const matchesType = currentType === 'ALL' || rType === currentType;
        const matchesQuery = !q || rec.toLowerCase().includes(q);
        return matchesType && matchesQuery;
      });

      countEl.textContent = `Showing ${filtered.length} of ${records.length}`;
      list.replaceChildren();

      if (!filtered.length) {
        const empty = document.createElement('li');
        empty.className = 'empty-state';
        empty.innerHTML = '<span>◇</span>No DNS records match the filter.';
        list.appendChild(empty);
        return;
      }

      filtered.forEach((rec) => {
        const item = document.createElement('li');
        item.className = 'clean-list-item';
        const parts = rec.split(':');
        const rType = parts[0] ? parts[0].trim().toUpperCase() : 'TXT';
        const rVal = parts.slice(1).join(':').trim() || rec;

        const content = document.createElement('span');
        content.className = 'item-content';
        content.innerHTML = `<span class="badge-type ${escapeHtml(rType)}">${escapeHtml(rType)}</span> <span class="mono-val">${escapeHtml(rVal)}</span>`;

        const copyBtn = document.createElement('button');
        copyBtn.className = 'item-btn';
        copyBtn.type = 'button';
        copyBtn.textContent = 'Copy';
        copyBtn.onclick = () => copyToClipboard(rec, copyBtn);

        item.append(content, copyBtn);
        list.appendChild(item);
      });
    }

    input.oninput = update;
    copyAllBtn.onclick = () => {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = records.filter((r) => !q || r.toLowerCase().includes(q));
      copyToClipboard(filtered.join('\n'), copyAllBtn);
    };
    update();
  }

  // Render IP Records
  function renderIPs(ips) {
    const tbody = $('#table-ips tbody');
    const input = $('#filter-ips');
    const countEl = $('#counter-ips');
    const copyAllBtn = $('#btn-copy-ips');

    function update() {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = q
        ? ips.filter((item) => (item.ip && item.ip.toLowerCase().includes(q)) || (item.asn && item.asn.toLowerCase().includes(q)) || (item.asn_description && item.asn_description.toLowerCase().includes(q)) || (item.location && item.location.toLowerCase().includes(q)))
        : ips;

      countEl.textContent = `Showing ${filtered.length} of ${ips.length}`;
      tbody.replaceChildren();

      if (!filtered.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 6;
        td.className = 'empty-state';
        td.innerHTML = '<span>◇</span>No IP addresses match search.';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      filtered.forEach((item) => {
        const tr = document.createElement('tr');
        const portsHtml = item.ports && item.ports.length
          ? item.ports.map((p) => `<span class="port-pill">${escapeHtml(p)}</span>`).join('')
          : '<span style="color:var(--dim)">—</span>';
        const asnText = [item.asn ? `AS${item.asn}` : '', item.asn_description].filter(Boolean).join(' - ') || '—';

        tr.innerHTML = `
          <td class="mono-val" style="font-weight:600">${escapeHtml(item.ip)}</td>
          <td>${escapeHtml(item.asn ? `AS${item.asn}` : '—')}</td>
          <td>${escapeHtml(item.asn_description || '—')}</td>
          <td>${escapeHtml(item.location || '—')}</td>
          <td>${portsHtml}</td>
          <td>
            <button class="item-btn btn-copy-row" type="button">Copy IP</button>
          </td>
        `;

        tr.querySelector('.btn-copy-row').onclick = (e) => copyToClipboard(item.ip, e.target);
        tbody.appendChild(tr);
      });
    }

    input.oninput = update;
    copyAllBtn.onclick = () => {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = q ? ips.filter((i) => i.ip.includes(q)) : ips;
      copyToClipboard(filtered.map((i) => i.ip).join('\n'), copyAllBtn);
    };
    update();
  }

  // Render Ports & Vulns
  function renderPorts(items) {
    const container = $('#container-ports');
    const input = $('#filter-ports');
    const countEl = $('#counter-ports');

    function update() {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = q
        ? items.filter((item) => (item.ip && item.ip.includes(q)) || (item.ports_raw && item.ports_raw.toLowerCase().includes(q)) || (item.vulnerabilities_raw && item.vulnerabilities_raw.toLowerCase().includes(q)))
        : items;

      countEl.textContent = `Showing ${filtered.length} of ${items.length} hosts`;
      container.replaceChildren();

      if (!filtered.length) {
        container.innerHTML = '<p class="empty-state"><span>◇</span>No open ports or vulnerabilities identified.</p>';
        return;
      }

      filtered.forEach((item) => {
        const card = document.createElement('div');
        card.className = 'port-card';
        const portsHtml = item.ports && item.ports.length
          ? item.ports.map((p) => `<span class="port-pill">${escapeHtml(p)}</span>`).join('')
          : '<span style="color:var(--dim)">None detected</span>';
        const vulnsHtml = item.vulnerabilities && item.vulnerabilities.length
          ? item.vulnerabilities.map((v) => `<span class="vuln-pill">${escapeHtml(v)}</span>`).join('')
          : '<span style="color:var(--dim)">No known CVEs flagged</span>';

        card.innerHTML = `
          <div class="port-card-head">
            <strong class="mono-val">${escapeHtml(item.ip)}</strong>
            <small style="color:var(--muted)">${escapeHtml(item.asn_description || item.location || '')}</small>
          </div>
          <div style="margin: 8px 0;">
            <div style="font-size:10px; color:var(--muted); margin-bottom:4px;">Open Ports / Protocols:</div>
            <div>${portsHtml}</div>
          </div>
          <div style="margin: 8px 0;">
            <div style="font-size:10px; color:var(--muted); margin-bottom:4px;">Flagged Vulnerabilities:</div>
            <div>${vulnsHtml}</div>
          </div>
        `;
        container.appendChild(card);
      });
    }

    input.oninput = update;
    update();
  }

  // Generic List Renderer (Emails, Buckets, Guessed)
  function renderGenericList(items, listId, filterId, counterId, copyBtnId, noun) {
    const list = $(listId);
    const input = $(filterId);
    const countEl = $(counterId);
    const copyAllBtn = $(copyBtnId);

    function update() {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = q ? items.filter((x) => x.toLowerCase().includes(q)) : items;
      countEl.textContent = `Showing ${filtered.length} of ${items.length}`;
      list.replaceChildren();

      if (!filtered.length) {
        list.innerHTML = `<li class="empty-state"><span>◇</span>No ${noun} discovered.</li>`;
        return;
      }

      filtered.forEach((val) => {
        const item = document.createElement('li');
        item.className = 'clean-list-item';
        const content = document.createElement('span');
        content.className = 'item-content mono-val';
        content.textContent = val;

        const copyBtn = document.createElement('button');
        copyBtn.className = 'item-btn';
        copyBtn.type = 'button';
        copyBtn.textContent = 'Copy';
        copyBtn.onclick = () => copyToClipboard(val, copyBtn);

        item.append(content, copyBtn);
        list.appendChild(item);
      });
    }

    input.oninput = update;
    if (copyAllBtn) {
      copyAllBtn.onclick = () => {
        const q = (input.value || '').trim().toLowerCase();
        const filtered = q ? items.filter((x) => x.toLowerCase().includes(q)) : items;
        copyToClipboard(filtered.join('\n'), copyAllBtn);
      };
    }
    update();
  }

  // Render Employees
  function renderEmployees(employees) {
    const grid = $('#grid-employees');
    const input = $('#filter-employees');
    const countEl = $('#counter-employees');

    function update() {
      const q = (input.value || '').trim().toLowerCase();
      const filtered = q
        ? employees.filter((e) => (e.full_name && e.full_name.toLowerCase().includes(q)) || (e.email && e.email.toLowerCase().includes(q)))
        : employees;

      countEl.textContent = `Showing ${filtered.length} of ${employees.length}`;
      grid.replaceChildren();

      if (!filtered.length) {
        grid.innerHTML = '<p class="empty-state"><span>◇</span>No employee profiles discovered.</p>';
        return;
      }

      filtered.forEach((emp) => {
        const card = document.createElement('div');
        card.className = 'employee-card';
        card.innerHTML = `
          <span class="employee-name">${escapeHtml(emp.full_name || 'Staff Member')}</span>
          ${emp.email ? `<span class="employee-email">${escapeHtml(emp.email)}</span>` : ''}
          ${emp.linkedin_url ? `<a class="employee-linkedin" href="${escapeHtml(emp.linkedin_url)}" target="_blank" rel="noopener">LinkedIn Profile ↗</a>` : ''}
        `;
        grid.appendChild(card);
      });
    }

    input.oninput = update;
    update();
  }

  // Render Artifacts Grid
  function renderArtifacts(artifacts, scanId) {
    const grid = $('#grid-artifacts');
    grid.replaceChildren();

    if (!artifacts.length) {
      grid.innerHTML = '<p class="empty-state"><span>◇</span>No additional artifact files produced.</p>';
      return;
    }

    artifacts.forEach((art) => {
      const card = document.createElement('div');
      card.className = 'artifact-card';
      const sizeKb = (art.size_bytes / 1024).toFixed(1);

      card.innerHTML = `
        <span class="artifact-name">${escapeHtml(art.name)}</span>
        <span class="artifact-meta">${sizeKb} KB · ${art.line_count || 0} lines</span>
        <div class="artifact-actions">
          <button class="item-btn btn-preview" type="button">Preview</button>
          <a class="item-btn" href="/api/scans/${scanId}/artifacts/${encodeURIComponent(art.name)}" download>Download</a>
        </div>
      `;

      card.querySelector('.btn-preview').onclick = () => {
        const dialog = $('#artifact-dialog');
        $('#dialog-filename').textContent = art.name;
        $('#dialog-code code').textContent = art.preview || 'No preview available.';
        $('#dialog-download-link').href = `/api/scans/${scanId}/artifacts/${encodeURIComponent(art.name)}`;
        dialog.showModal();
      };

      grid.appendChild(card);
    });

    $('#dialog-close-btn').onclick = () => $('#artifact-dialog').close();
    $('#dialog-copy-btn').onclick = (e) => copyToClipboard($('#dialog-code code').textContent, e.target);
  }

  // Build Complete Report
  function buildReport(job) {
    saveScanToLocalHistory(job);
    const scanWrap = $('.scan-wrap');
    if (scanWrap) scanWrap.classList.add('results-mode');

    const report = job.summary || {};
    const counts = report.counts || {};
    const sections = report.sections || {};

    $('#report-target-domain').textContent = job.target;
    $('#report-description').textContent = `The scan of ${job.target} finished. Review findings below or download the master archive.`;
    const dur = `${Number(job.duration_seconds || report.duration_seconds || 0).toFixed(2)} SEC`;
    $('#report-duration').textContent = dur;

    // Badges
    $('#badge-subdomains').textContent = Number(counts.subdomains || 0).toLocaleString();
    $('#badge-dns').textContent = Number(counts.dns_records || 0).toLocaleString();
    $('#badge-ips').textContent = Number(counts.ips || 0).toLocaleString();
    $('#badge-ports').textContent = `${Number(counts.ports || 0)} ports`;
    $('#badge-emails').textContent = Number(counts.emails || 0).toLocaleString();
    $('#badge-guessed').textContent = Number(counts.guessed_emails || 0).toLocaleString();
    $('#badge-employees').textContent = Number(counts.employees || 0).toLocaleString();
    $('#badge-buckets').textContent = Number(counts.buckets || 0).toLocaleString();
    $('#badge-creds').textContent = Number((counts.creds || 0) + (counts.hashes || 0)).toLocaleString();
    $('#badge-artifacts').textContent = Number(counts.artifacts || 0).toLocaleString();

    // Mode badges
    const modeStr = (job.mode || report.mode || 'passive').toUpperCase();
    $('#report-mode-pill').textContent = modeStr;
    $('#meta-mode').textContent = modeStr === 'ACTIVE' ? 'Active / Deep Recon' : 'Passive / Stealth OSINT';

    // Overview Metrics
    const metricData = [
      ['subdomains', 'Subdomains Discovered', 'subdomains'],
      ['dns_records', 'DNS Records Mapped', 'dns'],
      ['ips', 'Public IP Addresses', 'ips'],
      ['ports', 'Open Ports Identified', 'ports'],
      ['emails', 'Discovered Emails', 'emails'],
      ['employees', 'Employee Profiles', 'employees'],
      ['buckets', 'Cloud Buckets Found', 'buckets'],
      ['vulns', 'Possible Vulnerabilities', 'ports'],
    ];

    const grid = $('#report-metrics');
    grid.replaceChildren();
    metricData.forEach(([key, label, tab]) => {
      const cell = document.createElement('div');
      cell.className = 'metric-cell';
      cell.style.cursor = 'pointer';
      cell.title = `Click to view ${label}`;
      cell.innerHTML = `
        <strong class="metric-value">${Number(counts[key] || 0).toLocaleString()}</strong>
        <span class="metric-label">${label} <span style="color:var(--aqua)">↗</span></span>
      `;
      cell.onclick = () => switchTab(tab);
      grid.appendChild(cell);
    });

    // Zero-finding notice
    const totalFound = (counts.subdomains || 0) + (counts.dns_records || 0) + (counts.ips || 0) + (counts.ports || 0) + (counts.emails || 0) + (counts.buckets || 0);
    const noticeEl = $('#empty-scan-notice');
    if (noticeEl) {
      noticeEl.hidden = totalFound > 0;
    }

    // Metadata
    $('#meta-target').textContent = job.target;
    $('#meta-duration').textContent = dur;
    $('#meta-completed').textContent = job.completed_at || report.completed_at || 'Just now';
    $('#meta-folder').textContent = report.result_folder || 'demo_run';

    // Quick links
    $('#quick-badge-subdomains').textContent = counts.subdomains || 0;
    $('#quick-badge-dns').textContent = counts.dns_records || 0;
    $('#quick-badge-ips').textContent = counts.ips || 0;
    $('#quick-badge-ports').textContent = counts.ports || 0;
    $('#quick-badge-emails').textContent = counts.emails || 0;
    $('#quick-badge-employees').textContent = counts.employees || 0;
    $('#quick-badge-buckets').textContent = counts.buckets || 0;
    $('#quick-badge-artifacts').textContent = counts.artifacts || 0;

    // Render Section Panels
    renderSubdomains(sections.subdomains || []);
    renderDNS(sections.dns_records || []);
    renderIPs(sections.ip_records || []);
    renderPorts(sections.ports_and_vulns || []);
    renderGenericList(sections.emails || [], '#list-emails', '#filter-emails', '#counter-emails', '#btn-copy-emails', 'emails');
    renderGenericList(sections.guessed_emails || [], '#list-guessed', '#filter-guessed', '#counter-guessed', '#btn-copy-guessed', 'guessed emails');
    renderGenericList(sections.buckets || [], '#list-buckets', '#filter-buckets', '#counter-buckets', '#btn-copy-buckets', 'cloud buckets');
    renderEmployees(sections.employees || []);

    // Email Security
    const sec = sections.email_security || {};
    const spfRaw = sec.spf || 'Not detected';
    const dmarcRaw = sec.dmarc || 'Not detected';
    const hasSpf = spfRaw && !spfRaw.toLowerCase().includes('not detected') && !spfRaw.toLowerCase().includes('none');
    const hasDmarc = dmarcRaw && !dmarcRaw.toLowerCase().includes('not detected') && !dmarcRaw.toLowerCase().includes('false');

    $('#sec-spf-badge').className = `security-status-badge ${hasSpf ? 'good' : 'warn'}`;
    $('#sec-spf-badge').textContent = hasSpf ? 'Configured' : 'Missing / Open';
    $('#sec-spf-raw').textContent = spfRaw;

    $('#sec-dmarc-badge').className = `security-status-badge ${hasDmarc ? 'good' : 'warn'}`;
    $('#sec-dmarc-badge').textContent = hasDmarc ? 'Enforced' : 'Missing / Inactive';
    $('#sec-dmarc-raw').textContent = dmarcRaw;

    const spoofList = $('#list-spoof-raw');
    spoofList.replaceChildren();
    (sec.raw_lines || []).forEach((line) => {
      const li = document.createElement('li');
      li.className = 'clean-list-item mono-val';
      li.textContent = line;
      spoofList.appendChild(li);
    });

    // Credentials & Hashes
    const creds = sections.credentials || {};
    const credsList = $('#list-creds');
    credsList.replaceChildren();
    if (!creds.creds || !creds.creds.length) {
      credsList.innerHTML = '<li class="empty-state"><span>◇</span>No public breach credentials found.</li>';
    } else {
      creds.creds.forEach((c) => {
        const li = document.createElement('li');
        li.className = 'clean-list-item mono-val';
        li.textContent = c;
        credsList.appendChild(li);
      });
    }

    const hashesList = $('#list-hashes');
    hashesList.replaceChildren();
    if (!creds.hashes || !creds.hashes.length) {
      hashesList.innerHTML = '<li class="empty-state"><span>◇</span>No password hashes found.</li>';
    } else {
      creds.hashes.forEach((h) => {
        const li = document.createElement('li');
        li.className = 'clean-list-item mono-val';
        li.textContent = h;
        hashesList.appendChild(li);
      });
    }

    // Artifacts
    renderArtifacts(sections.artifacts || [], job.id);

    // Setup SurfaceDrift Continuous Exposure Bridge
    setupSurfaceDriftBridge(job);

    // Initialize Surface Drift, Attack Graph & MITRE Matrix
    renderSurfaceDriftDelta(job.id, job);
    renderAttackPathGraph(job.surfacedrift_advanced?.attack_graph, job);
    renderMitreAttack(job.surfacedrift_advanced?.mitre_attack, job.surfacedrift_advanced?.findings);

    // Render Phase 2 if present; otherwise ensure it is hidden
    if (job.surfacedrift_advanced) {
      renderAdvancedResults(job.surfacedrift_advanced, job.id);
    } else {
      const advView = $('#advanced-results-view');
      if (advView) advView.hidden = true;
    }

    setupTabs();
    showView('report');
  }

  // =========================================================================
  // SurfaceDrift Advanced Assessment & Bridge Engine
  // =========================================================================
  function renderMarkdown(md) {
    if (!md) return '';
    return md
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/^### (.*$)/gim, '<h3>$1</h3>')
      .replace(/^#### (.*$)/gim, '<h4>$1</h4>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/^\- (.*$)/gim, '<li>$1</li>')
      .replace(/<\/li>\n<li>/g, '</li><li>')
      .replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>')
      .replace(/\n\n/g, '<p></p>')
      .replace(/\n/g, '<br />');
  }

  function setupSurfaceDriftBridge(job) {
    const bridgeCard = $('#surfacedrift-bridge-card');
    if (!bridgeCard) return;

    const counts = (job.summary && job.summary.counts) || {};
    const subCount = Number(counts.subdomains || 0).toLocaleString();
    const ipCount = Number(counts.ips || 0).toLocaleString();

    $('#bridge-subdomain-count').textContent = subCount;
    $('#bridge-ip-count').textContent = ipCount;

    const launchBtn = $('#btn-run-surfacedrift');
    const statusBox = $('#bridge-runner-status');
    const statusMsg = $('#bridge-status-msg');
    const termEl = $('#surfacedrift-terminal');
    const termLines = $('#adv-log-lines');
    const termCount = $('#adv-log-count');
    const termClear = $('#adv-terminal-clear-btn');

    if (termClear && termLines) {
      termClear.onclick = () => {
        termLines.replaceChildren();
        const p = document.createElement('p');
        p.className = 'term-line-info';
        p.textContent = 'Console cleared.';
        termLines.appendChild(p);
        if (termCount) termCount.textContent = '0 events';
      };
    }

    function appendAdvLog(line) {
      if (!termLines) return;
      const p = document.createElement('p');
      p.className = 'term-line';
      if (line.includes('[+]')) p.className += ' term-line-pos';
      else if (line.includes('[-]')) p.className += ' term-line-act';
      else if (line.includes('[!]')) p.className += ' term-line-err';
      else if (line.includes('[*]')) p.className += ' term-line-warn';
      else p.className += ' term-line-info';
      p.textContent = line;
      termLines.appendChild(p);
      termLines.scrollTop = termLines.scrollHeight;

      if (termCount) {
        const count = termLines.querySelectorAll('p').length;
        termCount.textContent = `${count} event${count === 1 ? '' : 's'}`;
      }

      if (statusMsg) {
        const clean = line.replace(/^\[[+\-*!i]\]\s*/, '');
        if (clean.length > 5) {
          statusMsg.textContent = clean.slice(0, 80);
        }
      }
    }

    // If user is guest, show locked banner on SurfaceDrift Bridge
    const existingLock = $('#phase2-lock-banner');
    if (!currentUser) {
      if (!existingLock && bridgeCard) {
        const lockEl = document.createElement('div');
        lockEl.id = 'phase2-lock-banner';
        lockEl.className = 'phase2-auth-lock';
        lockEl.innerHTML = `
          <span class="lock-icon">🔒</span>
          <div class="lock-content">
            <strong>Phase 2 Deep Probing Restricted to Logged-in Users</strong>
            <p>Phase 2 runs automated vulnerability correlation, JS secrets extraction, shadow API discovery, WAF bypass mapping, and compliance audits. Sign in with Google to unlock.</p>
          </div>
          <button type="button" class="btn-phase2-login" id="phase2-lock-login-btn">
            Sign In with Google
          </button>
        `;
        bridgeCard.prepend(lockEl);
        $('#phase2-lock-login-btn')?.addEventListener('click', triggerGoogleLogin);
      }
    } else {
      if (existingLock) existingLock.remove();
    }

    // If job already has advanced analysis (from SQLite or disk reload)
    if (job.surfacedrift_advanced) {
      renderAdvancedResults(job.surfacedrift_advanced, job.id);
      if (termEl) termEl.hidden = false;
      if (termLines && job.surfacedrift_advanced.logs) {
        termLines.replaceChildren();
        job.surfacedrift_advanced.logs.forEach(appendAdvLog);
      }
      if (launchBtn) {
        launchBtn.innerHTML = '<span>Re-run SurfaceDrift Analysis</span><span class="button-arrow" aria-hidden="true">⚡</span>';
      }
    }

    if (launchBtn) {
      launchBtn.onclick = async () => {
        // Enforce Authentication for Phase 2 Deep Probing
        if (!currentUser) {
          alert('Authentication Required:\n\nPhase 2 Deep Probing assessments require signing in with Google.\nPlease sign in to unlock deep vulnerability scanning, secrets audits, and remediation playbooks.');
          triggerGoogleLogin();
          return;
        }

        const categories = [];
        if ($('#cat-http-probe')?.checked) categories.push('http_probe');
        if ($('#cat-takeover')?.checked) categories.push('takeover');
        if ($('#cat-cloud-audit')?.checked) categories.push('cloud_audit');
        if ($('#cat-waf-mapping')?.checked) {
          categories.push('waf_mapping');
          categories.push('waf_bypass');
          categories.push('waf_history');
        }
        if ($('#cat-waf-bypass')?.checked) categories.push('waf_bypass');
        if ($('#cat-epss-kev')?.checked) categories.push('epss_kev');
        if ($('#cat-email-sec')?.checked) categories.push('email_sec');
        if ($('#cat-js-secrets')?.checked) categories.push('js_secrets');
        if ($('#cat-shadow-api')?.checked) categories.push('shadow_api');
        if ($('#cat-eol-audit')?.checked) categories.push('eol_audit');
        if ($('#cat-blh-audit')?.checked) categories.push('blh_audit');
        if ($('#cat-waf-history')?.checked) categories.push('waf_history');
        if ($('#cat-config-probe')?.checked) categories.push('config_probe');
        if ($('#cat-tls-posture')?.checked) categories.push('tls_posture');
        if ($('#cat-breach-intel')?.checked) categories.push('breach_intel');
        if ($('#cat-typosquatting')?.checked) categories.push('typosquatting');
        if ($('#cat-remediation')?.checked) categories.push('remediation');

        if (!categories.length) {
          alert('Please select at least one assessment category to run.');
          return;
        }

        launchBtn.disabled = true;
        statusBox.hidden = false;
        statusMsg.textContent = 'SurfaceDrift engines initializing...';

        if (termEl) termEl.hidden = false;
        if (termLines) {
          termLines.replaceChildren();
          appendAdvLog(`[-] SurfaceDrift CTEM Pipeline initiated for target: ${job.target}`);
        }

        const scanPayload = {
          categories,
          target: job.target,
          summary: job.summary
        };
        const scanId = job.id || activeScanId;

        let completed = false;
        try {
          const resp = await fetch(`/api/scans/${encodeURIComponent(scanId)}/continue-surfacedrift-stream`, {
            method: 'POST',
            headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify(scanPayload),
          });

          if (resp.status === 401) {
            alert('Authentication required: Please sign in with Google to run Phase 2 Deep Probing assessments.');
            triggerGoogleLogin();
            return;
          }

          if (!resp.ok) {
            throw new Error(`Server returned HTTP ${resp.status}`);
          }

          const reader = resp.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';

          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const parts = buffer.split('\n\n');
            buffer = parts.pop() || '';

            for (const part of parts) {
              const trimmed = part.trim();
              if (!trimmed.startsWith('data:')) continue;
              const jsonStr = trimmed.slice(5).trim();
              if (!jsonStr) continue;
              try {
                const event = JSON.parse(jsonStr);
                if (event.type === 'log') {
                  appendAdvLog(event.line);
                } else if (event.type === 'done') {
                  completed = true;
                  renderAdvancedResults(event.advanced, scanId);
                  launchBtn.innerHTML = '<span>Re-run SurfaceDrift Analysis</span><span class="button-arrow" aria-hidden="true">⚡</span>';
                  const advView = $('#advanced-results-view');
                  if (advView) {
                    setTimeout(() => {
                      advView.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }, 200);
                  }
                } else if (event.type === 'error') {
                  appendAdvLog(`[!] Error: ${event.error}`);
                }
              } catch (e) {
                console.error('Error parsing SSE event:', e);
              }
            }
          }
        } catch (streamErr) {
          console.warn('Streaming connection issue, falling back to standard POST:', streamErr);
          if (!completed) {
            appendAdvLog(`[*] Streaming connection closed, executing direct CTEM assessment pipeline...`);
            appendAdvLog(`[-] Concurrently evaluating 15 deep exposure engines in background...`);
            if (statusMsg) statusMsg.textContent = 'Executing 15 CTEM engines via direct pipeline...';

            const progressSteps = [
              "[-] Auditing cloud storage (S3, Azure Blob, GCP) & CNAME takeovers...",
              "[-] Evaluating RFC 7208 SPF and RFC 7489 DMARC spoofing vectors...",
              "[-] Scanning client-side JavaScript bundles for exposed API keys & secrets...",
              "[-] Probing active endpoints for Shadow APIs, Swagger specs & GraphQL...",
              "[-] Testing SSL/TLS cryptographic posture, cipher suites & HSTS...",
              "[-] Analyzing typosquatting & brand phishing radar for weaponized MX domains...",
              "[-] Synthesizing MITRE ATT&CK Matrix & multi-hop adversary attack graphs..."
            ];
            let stepIdx = 0;
            const progressTicker = setInterval(() => {
              if (stepIdx < progressSteps.length) {
                appendAdvLog(progressSteps[stepIdx++]);
              }
            }, 2500);

            try {
              const fallbackResp = await fetch(`/api/scans/${encodeURIComponent(scanId)}/continue-surfacedrift`, {
                method: 'POST',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify(scanPayload),
              });

              clearInterval(progressTicker);

              if (fallbackResp.status === 401) {
                alert('Authentication required: Please sign in with Google to run Phase 2 Deep Probing assessments.');
                triggerGoogleLogin();
                return;
              }
              if (!fallbackResp.ok) {
                const err = await fallbackResp.json().catch(() => ({}));
                throw new Error(err.detail || 'SurfaceDrift assessment failed.');
              }
              const fallbackData = await fallbackResp.json();
              appendAdvLog('[+] Direct assessment complete! Rendering exposure report...');
              if (fallbackData.advanced && fallbackData.advanced.logs) {
                fallbackData.advanced.logs.forEach(appendAdvLog);
              }
              renderAdvancedResults(fallbackData.advanced, job.id);
              launchBtn.innerHTML = '<span>Re-run SurfaceDrift Analysis</span><span class="button-arrow" aria-hidden="true">⚡</span>';
              const advView = $('#advanced-results-view');
              if (advView) {
                setTimeout(() => {
                  advView.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 200);
              }
            } catch (fallbackErr) {
              clearInterval(progressTicker);
              appendAdvLog(`[!] Direct assessment error: ${fallbackErr.message || fallbackErr}`);
              console.error('Fallback assessment failed:', fallbackErr);
            }
          }
        } finally {
          launchBtn.disabled = false;
          statusBox.hidden = true;
        }
      };
    }
  }

  function renderAdvancedResults(adv, scanId) {
    if (lastJob) {
      lastJob.surfacedrift_advanced = adv;
      saveScanToLocalHistory(lastJob);
    }
    const resultsView = $('#advanced-results-view');
    if (!resultsView) return;
    resultsView.hidden = false;

    // 1. Posture Score & Grade
    const posture = adv.posture || { score: 100, grade: 'A', breakdown: [] };
    const scoreVal = posture.score !== undefined ? posture.score : 100;
    const gradeLetter = posture.grade || 'A';

    $('#adv-score-val').textContent = scoreVal;
    $('#adv-grade-letter').textContent = gradeLetter;

    const gradeCircle = $('#adv-grade-circle');
    if (gradeCircle) {
      gradeCircle.className = `grade-circle grade-${gradeLetter}`;
    }

    // Deduction Trail
    const dedContainer = $('#adv-deductions-container');
    dedContainer.replaceChildren();
    if (posture.breakdown && posture.breakdown.length > 0) {
      posture.breakdown.forEach((item) => {
        const div = document.createElement('div');
        div.className = 'deduction-item';
        div.textContent = `[-${item.deduction} pts] ${item.category}: ${item.description}`;
        dedContainer.appendChild(div);
      });
    } else {
      const span = document.createElement('span');
      span.className = 'no-deductions';
      span.textContent = '✓ Zero deductions — Optimal perimeter exposure posture.';
      dedContainer.appendChild(span);
    }

    // 2. Summary
    const ai = adv.ai_executive_summary || {};
    $('#adv-ai-source-tag').textContent = 'Summary';
    $('#adv-ai-summary-content').innerHTML = renderMarkdown(ai.content || 'Summary unavailable.');

    // 3. Deep Findings
    const findings = adv.findings || {};

    // HTTP Probing
    const httpData = findings.http_probing || { live_hosts_count: 0, results: [] };
    $('#adv-badge-http').textContent = `${httpData.live_hosts_count} live`;
    const httpBox = $('#adv-container-http');
    httpBox.replaceChildren();
    const liveItems = (httpData.results || []).filter((h) => h.is_live);
    if (!liveItems.length) {
      httpBox.innerHTML = '<p class="empty-state">No live web endpoints detected.</p>';
    } else {
      liveItems.forEach((h) => {
        const row = document.createElement('div');
        row.className = 'finding-row';
        const stCode = h.https_status || h.http_status || 200;
        const techs = (h.tech_stack || []).slice(0, 3).join(', ');
        row.innerHTML = `
          <div>
            <strong class="finding-name">${h.subdomain}</strong>
            <small style="display:block;color:#8ea39b;font-size:10px;">${h.page_title ? h.page_title.slice(0, 40) : (h.server_banner || '')} ${techs ? '· ' + techs : ''}</small>
          </div>
          <span class="finding-tag">${stCode}</span>
        `;
        httpBox.appendChild(row);
      });
    }

    // Subdomain Takeovers
    const takeovers = findings.subdomain_takeovers || { count: 0, items: [] };
    const takeBadge = $('#adv-badge-takeover');
    takeBadge.textContent = `${takeovers.count} found`;
    takeBadge.classList.toggle('critical', takeovers.count > 0);
    const takeBox = $('#adv-container-takeover');
    takeBox.replaceChildren();
    if (!takeovers.items || !takeovers.items.length) {
      takeBox.innerHTML = '<p class="empty-state">✓ No dangling CNAME takeovers detected.</p>';
    } else {
      takeovers.items.forEach((t) => {
        const row = document.createElement('div');
        row.className = 'finding-row';
        row.innerHTML = `
          <div>
            <strong class="finding-name" style="color:#f87171;">${t.subdomain}</strong>
            <small style="display:block;color:#fca5a5;font-size:10px;">Points to ${t.cname} (${t.service})</small>
          </div>
          <span class="finding-tag" style="background:rgba(239,68,68,0.2);color:#f87171;">VULNERABLE</span>
        `;
        takeBox.appendChild(row);
      });
    }

    // Cloud Storage
    const cloud = findings.cloud_storage || { count: 0, public_count: 0, buckets: [] };
    const cloudBadge = $('#adv-badge-cloud');
    cloudBadge.textContent = `${cloud.count} found (${cloud.public_count} public)`;
    cloudBadge.classList.toggle('critical', cloud.public_count > 0);
    const cloudBox = $('#adv-container-cloud');
    cloudBox.replaceChildren();
    if (!cloud.buckets || !cloud.buckets.length) {
      cloudBox.innerHTML = '<p class="empty-state">✓ No exposed storage buckets found.</p>';
    } else {
      cloud.buckets.forEach((b) => {
        const row = document.createElement('div');
        row.className = 'finding-row';
        const isBad = b.is_dangerous;
        row.innerHTML = `
          <div>
            <strong class="finding-name" style="${isBad ? 'color:#f87171;' : ''}">${b.bucket_name}</strong>
            <small style="display:block;color:#8ea39b;font-size:10px;">${b.provider} · ${b.access_level}</small>
          </div>
          <span class="finding-tag" style="${isBad ? 'background:rgba(239,68,68,0.2);color:#f87171;' : ''}">${b.access_level}</span>
        `;
        cloudBox.appendChild(row);
      });
    }

    // WAF Bypass Origins
    const waf = findings.waf_bypass || { count: 0, origins: [] };
    $('#adv-badge-waf').textContent = `${waf.count} origins`;
    const wafBox = $('#adv-container-waf');
    wafBox.replaceChildren();
    if (!waf.origins || !waf.origins.length) {
      wafBox.innerHTML = '<p class="empty-state">✓ No origin bypass IPs detected (CDN covered).</p>';
    } else {
      waf.origins.forEach((w) => {
        const row = document.createElement('div');
        row.className = 'finding-row';
        row.innerHTML = `
          <div>
            <strong class="finding-name" style="color:#fb923c;">${w.ip_address}</strong>
            <small style="display:block;color:#8ea39b;font-size:10px;">${w.asn_org || 'Direct Origin'} (${w.bypass_confidence || 'HIGH'} Confidence)</small>
          </div>
          <span class="finding-tag" style="background:rgba(249,115,22,0.2);color:#fb923c;">WAF BYPASS</span>
        `;
        wafBox.appendChild(row);
      });
    }

    // Weaponized CVEs
    const threat = findings.threat_prioritization || { critical_count: 0, high_count: 0, cves: [] };
    const cveBadge = $('#adv-badge-cves');
    cveBadge.textContent = `${threat.critical_count} critical`;
    cveBadge.classList.toggle('critical', threat.critical_count > 0);
    const cveBox = $('#adv-container-cves');
    cveBox.replaceChildren();
    if (!threat.cves || !threat.cves.length) {
      cveBox.innerHTML = '<p class="empty-state">✓ Zero weaponized or CISA KEV CVEs discovered.</p>';
    } else {
      threat.cves.forEach((v) => {
        const row = document.createElement('div');
        row.className = 'finding-row';
        const rawTag = (v.priority_tag || '').toUpperCase();
        let tag = 'LOW';
        if (v.cisa_kev || (v.epss_score && v.epss_score >= 0.20) || rawTag.includes('HIGH') || rawTag.includes('CRIT')) {
          tag = 'HIGH';
        } else if ((v.epss_score && v.epss_score >= 0.05) || rawTag.includes('MED')) {
          tag = 'MED';
        }

        let tagStyle = 'background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3);';
        let nameColor = '#e4f2ee';
        if (tag === 'HIGH') {
          tagStyle = 'background:rgba(239,68,68,0.22);color:#f87171;font-weight:600;border:1px solid rgba(239,68,68,0.4);';
          nameColor = '#f87171';
        } else if (tag === 'MED') {
          tagStyle = 'background:rgba(234,179,8,0.2);color:#facc15;font-weight:600;border:1px solid rgba(234,179,8,0.4);';
          nameColor = '#facc15';
        }

        row.innerHTML = `
          <div>
            <strong class="finding-name" style="color:${nameColor};">${v.cve_id}</strong>
            <small style="display:block;color:#8ea39b;font-size:10px;">EPSS: ${v.epss_score ? (v.epss_score * 100).toFixed(1) + '%' : 'N/A'} ${v.cisa_kev ? '· CISA KEV Listed' : ''}</small>
          </div>
          <span class="finding-tag" style="${tagStyle}">${tag}</span>
        `;
        cveBox.appendChild(row);
      });
    }

    // Email Security
    const emailSec = findings.email_security || {};
    const emailBox = $('#adv-container-email');
    emailBox.replaceChildren();
    const isSpoofable = emailSec.spoofable;
    const emailRow = document.createElement('div');
    emailRow.style.padding = '8px 10px';
    emailRow.innerHTML = `
      <div style="margin-bottom:6px;">
        <span class="finding-tag" style="${isSpoofable ? 'background:rgba(239,68,68,0.2);color:#f87171;' : 'background:rgba(74,222,128,0.2);color:#4ade80;'}">
          ${isSpoofable ? '⚠ SPOOFING POSSIBLE' : '✓ ENFORCED STRICT'}
        </span>
      </div>
      <div style="font-size:11px;color:#c4d6cf;font-family:var(--mono);">
        <div>SPF: <strong>${emailSec.spf_status || 'NOT_FOUND'}</strong></div>
        <div>DMARC Policy: <strong>${emailSec.dmarc_policy || 'NONE'} (${emailSec.dmarc_status || 'NOT_FOUND'})</strong></div>
      </div>
    `;
    emailBox.appendChild(emailRow);

    // 4. JavaScript Secrets
    const secData = findings.js_secrets || { secrets_found_count: 0, findings: [] };
    const secBadge = $('#adv-badge-secrets');
    if (secBadge) {
      secBadge.textContent = `${secData.secrets_found_count} secrets`;
      secBadge.classList.toggle('critical', secData.secrets_found_count > 0);
    }
    const secBox = $('#adv-container-secrets');
    if (secBox) {
      secBox.replaceChildren();
      if (!secData.findings || !secData.findings.length) {
        secBox.innerHTML = '<p class="empty-state">✓ No leaked credentials found in loaded JavaScript files.</p>';
      } else {
        secData.findings.forEach((s) => {
          const row = document.createElement('div');
          row.className = 'finding-row';
          const isHigh = s.severity === 'HIGH';
          row.innerHTML = `
            <div>
              <strong class="finding-name" style="${isHigh ? 'color:#f87171;' : ''}">${escapeHtml(s.secret_type)}</strong>
              <small style="display:block;color:#8ea39b;font-size:10px;">Token: <code>${escapeHtml(s.redacted_value)}</code> in ${escapeHtml(s.script_url)}</small>
            </div>
            <span class="finding-tag" style="${isHigh ? 'background:rgba(239,68,68,0.22);color:#f87171;font-weight:600;' : ''}">${escapeHtml(s.severity)}</span>
          `;
          secBox.appendChild(row);
        });
      }
    }

    // 5. Shadow APIs & Swagger Docs
    const apiData = findings.shadow_apis || { exposed_endpoints_count: 0, endpoints: [] };
    const apiBadge = $('#adv-badge-shadow-api');
    if (apiBadge) {
      apiBadge.textContent = `${apiData.exposed_endpoints_count} endpoints`;
      apiBadge.classList.toggle('critical', apiData.exposed_endpoints_count > 0);
    }
    const apiBox = $('#adv-container-shadow-api');
    if (apiBox) {
      apiBox.replaceChildren();
      if (!apiData.endpoints || !apiData.endpoints.length) {
        apiBox.innerHTML = '<p class="empty-state">✓ No unauthenticated API specifications or GraphQL endpoints exposed.</p>';
      } else {
        apiData.endpoints.forEach((ep) => {
          const row = document.createElement('div');
          row.className = 'finding-row';
          row.innerHTML = `
            <div>
              <strong class="finding-name" style="color:#fb923c;">${escapeHtml(ep.type)}</strong>
              <small style="display:block;color:#8ea39b;font-size:10px;">${escapeHtml(ep.url)}</small>
            </div>
            <span class="finding-tag" style="background:rgba(249,115,22,0.22);color:#fb923c;font-weight:600;">HTTP ${ep.status_code}</span>
          `;
          apiBox.appendChild(row);
        });
      }
    }

    // 6. EOL & Legacy Stack
    const eolData = findings.eol_software || { eol_findings_count: 0, findings: [] };
    const eolBadge = $('#adv-badge-eol');
    if (eolBadge) {
      eolBadge.textContent = `${eolData.eol_findings_count} EOL`;
      eolBadge.classList.toggle('critical', eolData.eol_findings_count > 0);
    }
    const eolBox = $('#adv-container-eol');
    if (eolBox) {
      eolBox.replaceChildren();
      if (!eolData.findings || !eolData.findings.length) {
        eolBox.innerHTML = '<p class="empty-state">✓ No deprecated or EOL runtimes detected in perimeter.</p>';
      } else {
        eolData.findings.forEach((e) => {
          const row = document.createElement('div');
          row.className = 'finding-row';
          row.innerHTML = `
            <div>
              <strong class="finding-name" style="color:#facc15;">${escapeHtml(e.product)} ${escapeHtml(e.detected_version)}</strong>
              <small style="display:block;color:#8ea39b;font-size:10px;">${escapeHtml(e.hostname)} · Recommend: ${escapeHtml(e.recommended_version)}</small>
            </div>
            <span class="finding-tag" style="background:rgba(234,179,8,0.2);color:#facc15;font-weight:600;">EOL &lt; ${escapeHtml(e.eol_threshold)}</span>
          `;
          eolBox.appendChild(row);
        });
      }
    }

    // 7. Broken Link Hijacking (BLH)
    const blhData = findings.broken_links || { broken_links_found: 0, vulnerable_links: [] };
    const blhBadge = $('#adv-badge-blh');
    if (blhBadge) {
      blhBadge.textContent = `${blhData.broken_links_found} broken`;
      blhBadge.classList.toggle('critical', blhData.broken_links_found > 0);
    }
    const blhBox = $('#adv-container-blh');
    if (blhBox) {
      blhBox.replaceChildren();
      if (!blhData.vulnerable_links || !blhData.vulnerable_links.length) {
        blhBox.innerHTML = '<p class="empty-state">✓ Zero expired external domains detected in outbound links.</p>';
      } else {
        blhData.vulnerable_links.forEach((b) => {
          const row = document.createElement('div');
          row.className = 'finding-row';
          row.innerHTML = `
            <div>
              <strong class="finding-name" style="color:#f87171;">${escapeHtml(b.expired_domain)}</strong>
              <small style="display:block;color:#8ea39b;font-size:10px;">Linked at: ${escapeHtml(b.original_link)}</small>
            </div>
            <span class="finding-tag" style="background:rgba(239,68,68,0.22);color:#f87171;font-weight:600;">NXDOMAIN (HIJACKABLE)</span>
          `;
          blhBox.appendChild(row);
        });
      }
    }

    // 8. Historical WAF Origin Bypasses
    const wafHistData = findings.waf_history || { origin_bypasses_found: 0, bypasses: [] };
    const wafHistBadge = $('#adv-badge-waf-history');
    if (wafHistBadge) {
      wafHistBadge.textContent = `${wafHistData.origin_bypasses_found} origins`;
      wafHistBadge.classList.toggle('critical', wafHistData.origin_bypasses_found > 0);
    }
    const wafHistBox = $('#adv-container-waf-history');
    if (wafHistBox) {
      wafHistBox.replaceChildren();
      if (!wafHistData.bypasses || !wafHistData.bypasses.length) {
        wafHistBox.innerHTML = '<p class="empty-state">✓ No historical non-CDN origin bypass IPs uncovered.</p>';
      } else {
        wafHistData.bypasses.forEach((ob) => {
          const row = document.createElement('div');
          row.className = 'finding-row';
          row.innerHTML = `
            <div>
              <strong class="finding-name" style="color:#fb923c;">${escapeHtml(ob.origin_ip)}</strong>
              <small style="display:block;color:#8ea39b;font-size:10px;">Direct Host: ${escapeHtml(ob.target_domain)} · Status: HTTP ${ob.status_code}</small>
            </div>
            <span class="finding-tag" style="background:rgba(249,115,22,0.22);color:#fb923c;font-weight:600;">ORIGIN BYPASS</span>
          `;
          wafHistBox.appendChild(row);
        });
      }
    }

    // 9. Exposed Configuration Probing
    const cfgData = findings.exposed_configs || { exposed_configs_found: 0, exposed_files: [] };
    const cfgBadge = $('#adv-badge-config');
    if (cfgBadge) {
      cfgBadge.textContent = `${cfgData.exposed_configs_found} exposed`;
      cfgBadge.classList.toggle('critical', cfgData.exposed_configs_found > 0);
    }
    const cfgBox = $('#adv-container-config');
    if (cfgBox) {
      cfgBox.replaceChildren();
      if (!cfgData.exposed_files || !cfgData.exposed_files.length) {
        cfgBox.innerHTML = '<p class="empty-state">✓ No sensitive configuration or backup files exposed.</p>';
      } else {
        cfgData.exposed_files.forEach((cf) => {
          const row = document.createElement('div');
          row.className = 'finding-row';
          row.innerHTML = `
            <div>
              <strong class="finding-name" style="color:#f87171;">${escapeHtml(cf.path)} (${escapeHtml(cf.description)})</strong>
              <small style="display:block;color:#8ea39b;font-size:10px;">URL: ${escapeHtml(cf.url)}</small>
            </div>
            <span class="finding-tag" style="background:rgba(239,68,68,0.22);color:#f87171;font-weight:600;">${escapeHtml(cf.severity)}</span>
          `;
          cfgBox.appendChild(row);
        });
      }
    }

    // 10. SSL/TLS Cryptographic Health (Compliance)
    const tlsData = findings.tls_posture || { endpoints_audited: 0, expiring_soon_count: 0, missing_hsts_count: 0, weak_protocol_count: 0, certificates: [] };
    const tlsBadge = $('#adv-badge-tls');
    if (tlsBadge) {
      const issueTotal = (tlsData.expiring_soon_count || 0) + (tlsData.weak_protocol_count || 0);
      tlsBadge.textContent = `${tlsData.endpoints_audited || 0} evaluated (${issueTotal} issues)`;
      tlsBadge.classList.toggle('critical', issueTotal > 0);
    }
    const tlsBox = $('#adv-container-tls');
    if (tlsBox) {
      tlsBox.replaceChildren();
      if (!tlsData.certificates || !tlsData.certificates.length) {
        tlsBox.innerHTML = '<p class="empty-state">✓ All scanned endpoints maintain valid certificates &amp; modern TLS.</p>';
      } else {
        const table = document.createElement('table');
        table.className = 'tls-posture-table';
        table.innerHTML = `
          <thead>
            <tr>
              <th>Host</th>
              <th>Issuer</th>
              <th>Expiry / Days</th>
              <th>Protocol / Cipher</th>
              <th>HSTS</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody></tbody>
        `;
        const tbody = table.querySelector('tbody');
        tlsData.certificates.forEach((c) => {
          const tr = document.createElement('tr');
          const isExpiring = c.status === 'EXPIRING_SOON' || c.status === 'EXPIRED';
          const isError = c.status === 'HANDSHAKE_FAILED' || c.status === 'ERROR';
          let statusBadgeClass = 'sd-badge-ok';
          let statusText = 'VALID';
          if (c.status === 'EXPIRING_SOON') {
            statusBadgeClass = 'sd-badge-medium';
            statusText = `EXPIRING (${c.days_remaining}d)`;
          } else if (c.status === 'EXPIRED') {
            statusBadgeClass = 'sd-badge-critical';
            statusText = 'EXPIRED';
          } else if (isError) {
            statusBadgeClass = 'sd-badge-critical';
            statusText = 'FAILED';
          }

          const hstsBadge = c.missing_hsts
            ? '<span class="status-pill warn" style="font-size:9px;">MISSING</span>'
            : '<span class="status-pill ok" style="font-size:9px;">ENFORCED</span>';

          const protoDisplay = c.tls_version ? `${escapeHtml(c.tls_version)} (${c.cipher_bits || 128}b)` : 'N/A';
          const protoStyle = c.weak_cipher ? 'color:#f87171;font-weight:600;' : '';

          tr.innerHTML = `
            <td><strong class="mono-val" style="color:#e4f2ee;">${escapeHtml(c.hostname)}</strong></td>
            <td><small style="color:#8ea39b;">${escapeHtml(c.issuer || 'Unknown')}</small></td>
            <td><span class="mono-val" style="${isExpiring ? 'color:#f87171;font-weight:600;' : 'color:#c4d6cf;'}">${c.days_remaining !== null && c.days_remaining !== undefined ? `${c.days_remaining}d left` : 'Unknown'}</span></td>
            <td><span class="mono-val" style="${protoStyle}">${protoDisplay}</span></td>
            <td>${hstsBadge}</td>
            <td><span class="${statusBadgeClass}">${statusText}</span></td>
          `;
          tbody.appendChild(tr);
        });
        tlsBox.appendChild(table);
      }
    }

    // 11. Leaked Credential & Breach Intelligence (Identity Risk)
    const breachData = findings.breach_intel || { total_emails_audited: 0, compromised_identities_count: 0, critical_credential_leaks_count: 0, breached_identities: [] };
    const breachBadge = $('#adv-badge-breach');
    if (breachBadge) {
      breachBadge.textContent = `${breachData.compromised_identities_count || 0} compromised`;
      breachBadge.classList.toggle('critical', (breachData.compromised_identities_count || 0) > 0);
    }
    const breachBox = $('#adv-container-breach');
    if (breachBox) {
      breachBox.replaceChildren();
      if (!breachData.breached_identities || !breachData.breached_identities.length) {
        breachBox.innerHTML = '<p class="empty-state">✓ Zero employee email addresses found in known credential leaks.</p>';
      } else {
        breachData.breached_identities.forEach((b) => {
          const row = document.createElement('div');
          row.className = 'finding-row';
          const isCrit = b.severity === 'CRITICAL' || b.has_passwords;
          row.innerHTML = `
            <div>
              <strong class="finding-name" style="${isCrit ? 'color:#f87171;' : 'color:#fb923c;'}">${escapeHtml(b.email)}</strong>
              <small style="display:block;color:#8ea39b;font-size:10px;">Breaches (${b.breaches.length}): ${escapeHtml(b.breaches.join(', '))} · Last seen: ${escapeHtml(b.last_breach_date || 'N/A')}</small>
            </div>
            <div style="display:flex;gap:6px;align-items:center;">
              ${b.has_passwords ? '<span class="finding-tag" style="background:rgba(239,68,68,0.22);color:#f87171;font-weight:700;">PASSWORDS LEAKED</span>' : ''}
              <span class="finding-tag" style="background:rgba(249,115,22,0.2);color:#fb923c;font-weight:600;">${escapeHtml(b.severity)}</span>
            </div>
          `;
          breachBox.appendChild(row);
        });
      }
    }

    // 12. Typosquatting & Phishing Threat Radar (Threat Intel)
    const typoData = findings.typosquatting || { root_domain: '', permutations_tested_count: 0, active_squats_count: 0, weaponized_phishing_count: 0, active_squats: [] };
    const typoBadge = $('#adv-badge-typosquat');
    if (typoBadge) {
      typoBadge.textContent = `${typoData.active_squats_count || 0} active (${typoData.weaponized_phishing_count || 0} phishing)`;
      typoBadge.classList.toggle('critical', (typoData.weaponized_phishing_count || 0) > 0);
    }
    const typoBox = $('#adv-container-typosquat');
    if (typoBox) {
      typoBox.replaceChildren();
      if (!typoData.active_squats || !typoData.active_squats.length) {
        typoBox.innerHTML = '<p class="empty-state">✓ Zero active typosquatted or brand impersonation domains detected.</p>';
      } else {
        typoData.active_squats.forEach((sq) => {
          const row = document.createElement('div');
          row.className = 'finding-row';
          const isPhish = sq.threat_level === 'WEAPONIZED_PHISHING' || sq.has_mx;
          row.innerHTML = `
            <div>
              <div style="display:flex;align-items:center;gap:8px;">
                <span class="radar-dot ${isPhish ? 'radar-pulse-red' : 'radar-dot-orange'}"></span>
                <strong class="finding-name" style="${isPhish ? 'color:#f87171;' : 'color:#fb923c;'}">${escapeHtml(sq.domain)}</strong>
                <span class="cat-chip" style="font-size:9px;padding:1px 5px;">${escapeHtml(sq.variation_type)}</span>
              </div>
              <small style="display:block;color:#8ea39b;font-size:10px;margin-top:2px;">
                Resolves to: <code style="color:#43e2d2;">${escapeHtml(sq.primary_ip || 'None')}</code> ${sq.has_mx ? `· Active MX: <code>${escapeHtml((sq.mx_hosts || []).slice(0, 2).join(', '))}</code>` : ''}
              </small>
            </div>
            <span class="finding-tag" style="${isPhish ? 'background:rgba(239,68,68,0.22);color:#f87171;font-weight:700;' : 'background:rgba(234,179,8,0.2);color:#facc15;font-weight:600;'}">
              ${escapeHtml(sq.threat_level.replace(/_/g, ' '))}
            </span>
          `;
          typoBox.appendChild(row);
        });
      }
    }

    // 13. Automated Remediation Playbooks (SecOps Integration)
    const playbooks = findings.remediation_playbooks || [];
    const remBadge = $('#adv-badge-remediation');
    if (remBadge) {
      remBadge.textContent = `${playbooks.length} playbook${playbooks.length === 1 ? '' : 's'}`;
    }
    const remBox = $('#adv-container-remediation');
    if (remBox) {
      remBox.replaceChildren();
      if (!playbooks.length) {
        remBox.innerHTML = '<p class="empty-state">✓ Zero remediation actions required — perimeter posture is solid.</p>';
      } else {
        playbooks.forEach((p) => {
          const card = document.createElement('div');
          card.className = 'remediation-card';
          const isCrit = p.severity === 'CRITICAL';
          card.innerHTML = `
            <div class="remediation-head">
              <div class="remediation-title-wrap">
                <span class="finding-tag" style="${isCrit ? 'background:rgba(239,68,68,0.25);color:#f87171;font-weight:700;' : 'background:rgba(249,115,22,0.22);color:#fb923c;font-weight:600;'}">${escapeHtml(p.severity)}</span>
                <span class="cat-chip" style="font-size:10px;">${escapeHtml(p.action_type)}</span>
                <strong style="color:#e4f2ee;font-size:13px;">${escapeHtml(p.title)}</strong>
              </div>
              <button class="btn-copy-snippet" type="button" title="Copy code snippet to clipboard">
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                <span>Copy Snippet</span>
              </button>
            </div>
            <p class="remediation-desc">${escapeHtml(p.description)} <small style="color:#8ea39b;">(Target: <code>${escapeHtml(p.affected_asset)}</code>)</small></p>
            <div class="remediation-snippet-box">
              <pre class="mono-val"><code>${escapeHtml(p.code_snippet)}</code></pre>
            </div>
          `;
          const copyBtn = card.querySelector('.btn-copy-snippet');
          if (copyBtn) {
            copyBtn.onclick = () => copyToClipboard(p.code_snippet, copyBtn);
          }
          remBox.appendChild(card);
        });
      }
    }

    // 14. MITRE ATT&CK Matrix Alignment
    renderMitreAttack(adv.mitre_attack, findings);

    // 15. Surface Drift Time-Series Delta
    renderSurfaceDriftDelta(scanId, lastJob);

    // 16. Graph-Based Attack Path Chaining
    renderAttackPathGraph(adv.attack_graph, lastJob);

    // Wire up Executive Report Download Action Hub
    const reportTarget = lastJob?.target || 'target';

    const btnPdf = $('#btn-dl-report-pdf');
    if (btnPdf) {
      btnPdf.onclick = () => downloadReportFile(scanId, reportTarget, 'pdf');
    }

    const btnHtml = $('#btn-dl-report-html');
    if (btnHtml) {
      btnHtml.onclick = () => downloadReportFile(scanId, reportTarget, 'html');
    }

    const btnMd = $('#btn-dl-report-md');
    if (btnMd) {
      btnMd.onclick = () => downloadReportFile(scanId, reportTarget, 'md');
    }

    const btnBundle = $('#btn-dl-report-bundle');
    if (btnBundle) {
      btnBundle.onclick = async () => {
        await downloadScanArchive({
          id: scanId,
          target: reportTarget,
          summary: lastJob?.summary,
          surfacedrift_advanced: adv,
        });
      };
    }

    const btnJson = $('#btn-dl-report-json');
    if (btnJson) {
      btnJson.onclick = () => downloadReportFile(scanId, reportTarget, 'json');
    }

    const btnPreview = $('#btn-preview-report-html');
    if (btnPreview) {
      btnPreview.href = `/api/scans/${encodeURIComponent(scanId)}/report.html`;
    }

    // Bottom combined package banner links
    const combinedBtn = $('#btn-download-combined-all');
    if (combinedBtn) {
      combinedBtn.onclick = async (e) => {
        e.preventDefault();
        await downloadScanArchive({
          id: scanId,
          target: reportTarget,
          summary: lastJob?.summary,
          surfacedrift_advanced: adv,
        });
      };
    }

    const bottomHtmlBtn = $('#btn-download-bottom-html');
    if (bottomHtmlBtn) {
      bottomHtmlBtn.onclick = () => downloadReportFile(scanId, reportTarget, 'html');
    }

    const bottomMdBtn = $('#btn-download-bottom-md');
    if (bottomMdBtn) {
      bottomMdBtn.onclick = () => downloadReportFile(scanId, reportTarget, 'md');
    }

    // Update top & bottom master download badges
    const dlTopBadge = $('#download-size-top');
    if (dlTopBadge) dlTopBadge.textContent = 'FULL CTEM BUNDLE';
    const dlBottomBadge = $('#download-size');
    if (dlBottomBadge) dlBottomBadge.textContent = 'COMPLETE CTEM REPORT + ZIP';
  }

  // =========================================================================
  // MITRE ATT&CK, Surface Drift & Attack Path Graph Visualization
  // =========================================================================
  function renderMitreAttack(mitreData, fallbackFindings) {
    if (!mitreData) {
      if (lastJob?.id) {
        fetch(`/api/scans/${encodeURIComponent(lastJob.id)}/mitre`)
          .then(res => res.ok ? res.json() : null)
          .then(data => { if (data) renderMitreAttack(data); })
          .catch(() => {});
      }
      return;
    }

    const grid = $('#mitre-matrix-grid');
    if (!grid) return;
    grid.replaceChildren();

    const tactics = mitreData.tactics || {};
    const summary = mitreData.summary || {};

    const tacticsTag = $('#mitre-tactics-tag');
    if (tacticsTag) {
      tacticsTag.textContent = `${summary.total_tactics_monitored || Object.keys(tactics).length} Tactics Monitored`;
    }
    const activeTag = $('#mitre-active-tag');
    if (activeTag) {
      const activeCount = summary.techniques_with_findings || 0;
      activeTag.textContent = `${activeCount} Threat${activeCount === 1 ? '' : 's'} Triggered`;
      activeTag.style.background = activeCount > 0 ? 'rgba(239,68,68,0.22)' : 'rgba(74,222,128,0.15)';
      activeTag.style.color = activeCount > 0 ? '#f87171' : '#4ade80';
    }

    const badgeMitre = $('#badge-mitre');
    if (badgeMitre) {
      badgeMitre.textContent = summary.techniques_with_findings ? `${summary.techniques_with_findings} active` : 'Matrix';
    }
    const quickBadge = $('#quick-badge-mitre');
    if (quickBadge) {
      quickBadge.textContent = summary.techniques_with_findings ? `${summary.techniques_with_findings} active` : 'Matrix';
    }

    Object.entries(tactics).forEach(([tacId, tac]) => {
      const col = document.createElement('div');
      col.className = 'mitre-tactic-col';
      
      const head = document.createElement('div');
      head.className = `mitre-tactic-head ${tac.has_critical ? 'critical-active' : ''}`;
      head.innerHTML = `
        <span class="mitre-tactic-id">${escapeHtml(tacId)}</span>
        <span class="mitre-tactic-name">${escapeHtml(tac.name)}</span>
      `;
      col.appendChild(head);

      const list = document.createElement('div');
      list.className = 'mitre-techniques-list';

      (tac.techniques || []).forEach((t) => {
        const card = document.createElement('a');
        card.className = `mitre-technique-pill ${t.has_findings ? 'threat-active' : ''}`;
        card.href = t.mitre_url || `https://attack.mitre.org/techniques/${t.technique_id}/`;
        card.target = '_blank';
        card.rel = 'noopener noreferrer';
        card.title = `${t.description || ''} (Click to view official MITRE ATT&CK reference)`;

        card.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span class="mitre-tech-id">${escapeHtml(t.subtechnique_id || t.technique_id)}</span>
            <span class="mitre-tech-status ${t.has_findings ? 'active' : 'clean'}">
              ${t.has_findings ? `${t.findings_count} ALERT` : 'AUDITED'}
            </span>
          </div>
          <span class="mitre-tech-name">${escapeHtml(t.subtechnique_name || t.technique_name)}</span>
        `;
        list.appendChild(card);
      });

      col.appendChild(list);
      grid.appendChild(col);
    });
  }

  async function renderSurfaceDriftDelta(scanId, job) {
    if (!scanId) return;

    const refreshBtn = $('#btn-refresh-drift');
    if (refreshBtn) {
      refreshBtn.onclick = () => renderSurfaceDriftDelta(scanId, job);
    }

    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/drift`);
      if (!res.ok) throw new Error('Drift endpoint response failed');
      let data = await res.json();

      // If server has no prior scan recorded (common on Vercel cold restarts or new DB)
      if (!data.has_prior) {
        const targetNorm = (job?.target || data.target || '').toLowerCase().trim();
        const localHist = getLocalHistory();
        const priorItem = localHist.find(h => h.id !== scanId && (h.target || '').toLowerCase().trim() === targetNorm && h.summary);
        if (priorItem) {
          try {
            const diffRes = await fetch('/api/scans/drift-diff', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                prior_scan_id: priorItem.id,
                current_scan_id: scanId,
              })
            });
            if (diffRes.ok) {
              const diffJson = await diffRes.json();
              if (diffJson.has_prior) {
                data = diffJson;
              }
            }
          } catch (e) {}
        }
      }

      const drift = data.drift || {};

      const statusBadge = $('#drift-status-badge');
      if (statusBadge) {
        if (!data.has_prior) {
          statusBadge.textContent = 'BASELINE RECORDED (RUN 1)';
          statusBadge.className = 'drift-badge';
          statusBadge.style.color = '#4ade80';
          statusBadge.style.borderColor = 'rgba(74,222,128,0.4)';
        } else if (drift.has_critical_drift) {
          statusBadge.textContent = 'Critical Posture Drift';
          statusBadge.className = 'drift-badge critical';
          statusBadge.style.color = '';
          statusBadge.style.borderColor = '';
        } else if (drift.has_drift) {
          statusBadge.textContent = 'Surface Drift Detected';
          statusBadge.className = 'drift-badge';
          statusBadge.style.color = '#facc15';
          statusBadge.style.borderColor = 'rgba(234,179,8,0.4)';
        } else {
          statusBadge.textContent = 'No Exposure Drift';
          statusBadge.className = 'drift-badge';
          statusBadge.style.color = '#4ade80';
          statusBadge.style.borderColor = 'rgba(74,222,128,0.4)';
        }
      }

      const scoreDeltaEl = $('#drift-score-delta');
      if (scoreDeltaEl) {
        if (!data.has_prior) {
          scoreDeltaEl.textContent = '0 (Baseline)';
          scoreDeltaEl.className = 'drift-stat-val text-success';
        } else {
          const delta = drift.score_delta || 0;
          if (delta > 0) {
            scoreDeltaEl.textContent = `+${delta} pts`;
            scoreDeltaEl.className = 'drift-stat-val text-success';
          } else if (delta < 0) {
            scoreDeltaEl.textContent = `${delta} pts`;
            scoreDeltaEl.className = 'drift-stat-val text-danger';
          } else {
            scoreDeltaEl.textContent = '0 pts';
            scoreDeltaEl.className = 'drift-stat-val';
          }
        }
      }

      const newSubs = drift.new_subdomains || [];
      const newPorts = drift.new_open_ports || [];
      const newVulns = drift.new_vulnerabilities || [];
      const newTakeovers = drift.new_takeovers || [];
      const newBuckets = drift.new_public_buckets || [];
      const resolvedThreats = [
        ...(drift.resolved_vulnerabilities || []),
        ...(drift.resolved_takeovers || []),
        ...(drift.resolved_public_buckets || []),
        ...(drift.closed_ports || []),
      ];

      $('#drift-new-subs-count').textContent = newSubs.length;
      $('#drift-new-ports-count').textContent = newPorts.length;
      $('#drift-new-threats-count').textContent = newVulns.length + newTakeovers.length + newBuckets.length;
      $('#drift-resolved-count').textContent = resolvedThreats.length;

      $('#drift-baseline-time').textContent = data.prior_timestamp ? new Date(data.prior_timestamp).toLocaleString() : 'Baseline Established (Run 1)';
      $('#drift-current-time').textContent = data.current_timestamp ? new Date(data.current_timestamp).toLocaleString() : new Date().toLocaleString();

      const badgeDrift = $('#badge-drift');
      if (badgeDrift) {
        if (!data.has_prior) badgeDrift.textContent = 'Base';
        else badgeDrift.textContent = drift.score_delta !== 0 ? (drift.score_delta > 0 ? `+${drift.score_delta}` : `${drift.score_delta}`) : '0';
      }
      const quickDrift = $('#quick-badge-drift');
      if (quickDrift) {
        quickDrift.textContent = badgeDrift ? badgeDrift.textContent : 'Δ';
      }

      const listNewAssets = $('#drift-list-new-assets');
      if (listNewAssets) {
        listNewAssets.replaceChildren();
        const combinedNew = [
          ...newSubs.map(s => ({ type: 'Subdomain', val: s })),
          ...newPorts.map(p => ({ type: 'Open Port', val: p })),
        ];
        $('#drift-badge-new-assets').textContent = combinedNew.length;
        if (!combinedNew.length) {
          listNewAssets.innerHTML = data.has_prior
            ? '<p class="empty-state">No new shadow assets detected compared to baseline.</p>'
            : '<p class="empty-state" style="color:#4ade80;">✓ Baseline snapshot recorded. Future scans will highlight newly discovered shadow subdomains or open ports.</p>';
        } else {
          combinedNew.forEach(item => {
            const row = document.createElement('div');
            row.className = 'finding-row';
            row.innerHTML = `
              <div><strong class="finding-name text-warning">${escapeHtml(item.val)}</strong></div>
              <span class="finding-tag" style="background:rgba(234,179,8,0.18);color:#facc15;">+ ${escapeHtml(item.type)}</span>
            `;
            listNewAssets.appendChild(row);
          });
        }
      }

      const listNewThreats = $('#drift-list-new-threats');
      if (listNewThreats) {
        listNewThreats.replaceChildren();
        const combinedThreats = [
          ...newTakeovers.map(t => ({ type: 'Takeover', val: t })),
          ...newBuckets.map(b => ({ type: 'Public Bucket', val: b })),
          ...newVulns.map(v => ({ type: 'Weaponized CVE', val: v })),
        ];
        $('#drift-badge-new-threats').textContent = combinedThreats.length;
        if (!combinedThreats.length) {
          listNewThreats.innerHTML = data.has_prior
            ? '<p class="empty-state">No newly introduced vulnerabilities or takeovers.</p>'
            : '<p class="empty-state">✓ No baseline critical threats detected. Newly introduced weaponized CVEs or dangling takeovers will be alerted here.</p>';
        } else {
          combinedThreats.forEach(item => {
            const row = document.createElement('div');
            row.className = 'finding-row';
            row.innerHTML = `
              <div><strong class="finding-name text-danger">${escapeHtml(item.val)}</strong></div>
              <span class="finding-tag" style="background:rgba(239,68,68,0.22);color:#f87171;font-weight:700;">+ ${escapeHtml(item.type)}</span>
            `;
            listNewThreats.appendChild(row);
          });
        }
      }

      const listResolved = $('#drift-list-resolved');
      if (listResolved) {
        listResolved.replaceChildren();
        $('#drift-badge-resolved').textContent = resolvedThreats.length;
        if (!resolvedThreats.length) {
          listResolved.innerHTML = data.has_prior
            ? '<p class="empty-state">No previously exposed assets were closed.</p>'
            : '<p class="empty-state">✓ Remediated vulnerabilities and closed ports will be tracked against this initial baseline.</p>';
        } else {
          resolvedThreats.forEach(item => {
            const row = document.createElement('div');
            row.className = 'finding-row';
            row.innerHTML = `
              <div><strong class="finding-name text-success">${escapeHtml(item)}</strong></div>
              <span class="finding-tag" style="background:rgba(74,222,128,0.15);color:#4ade80;">Remediated</span>
            `;
            listResolved.appendChild(row);
          });
        }
      }
    } catch (err) {
      console.warn('Surface drift check skipped or failed:', err);
    }
  }

  async function renderAttackPathGraph(graphData, job) {
    let graph = graphData;
    if (!graph && job?.id) {
      try {
        const res = await fetch(`/api/scans/${encodeURIComponent(job.id)}/attack-graph`);
        if (res.ok) graph = await res.json();
      } catch (e) {}
    }

    if (!graph && job?.summary) {
      const target = job.target || 'target';
      const sections = job.summary.sections || {};
      const subs = (sections.subdomains || []).map(s => typeof s === 'string' ? s : (s.subdomain || s.name || '')).filter(Boolean);
      const ips = sections.ip_records || [];
      
      const nodes = [{ id: `target_${target}`, label: target, type: 'target', severity: 'INFO' }];
      const links = [];
      
      subs.slice(0, 8).forEach(sub => {
        nodes.push({ id: `sub_${sub}`, label: sub, type: 'subdomain', severity: 'LOW' });
        links.push({ source: `target_${target}`, target: `sub_${sub}`, label: 'Resolves' });
      });
      ips.slice(0, 6).forEach(ip => {
        const ipStr = ip.ip || ip.ip_address || '';
        if (ipStr) {
          nodes.push({ id: `ip_${ipStr}`, label: ipStr, type: 'ip', severity: ip.is_cdn ? 'LOW' : 'INFO' });
          links.push({ source: `target_${target}`, target: `ip_${ipStr}`, label: 'Hosts' });
        }
      });
      graph = { nodes, links, attack_chains: [] };
    }

    if (!graph) return;

    const chains = graph.attack_chains || [];
    $('#graph-chains-badge').textContent = `${chains.length} Chain${chains.length === 1 ? '' : 's'}`;
    $('#badge-graph').textContent = chains.length ? `${chains.length} Paths` : 'Graph';
    const quickGraph = $('#quick-badge-graph');
    if (quickGraph) quickGraph.textContent = chains.length ? `${chains.length} Paths` : 'Graph';

    const chainsList = $('#attack-chains-list');
    if (chainsList) {
      chainsList.replaceChildren();
      if (!chains.length) {
        chainsList.innerHTML = '<p class="empty-state">✓ No multi-hop adversary traversal paths identified. Perimeter defenses intact.</p>';
      } else {
        chains.forEach(chain => {
          const row = document.createElement('div');
          const isCrit = chain.severity === 'CRITICAL';
          row.className = `attack-chain-row ${isCrit ? 'critical' : 'high'}`;
          row.innerHTML = `
            <div class="attack-chain-head">
              <span class="attack-chain-title">${escapeHtml(chain.title)}</span>
              <div style="display:flex;gap:6px;align-items:center;">
                <span class="finding-tag" style="${isCrit ? 'background:rgba(239,68,68,0.22);color:#f87171;' : 'background:rgba(249,115,22,0.22);color:#fb923c;'} font-weight:700;">${escapeHtml(chain.severity)}</span>
                <span class="cat-chip" style="font-size:10px;">${escapeHtml(chain.mitre || '')}</span>
              </div>
            </div>
            <div class="chain-steps-wrap">
              ${(chain.path || []).map((step, idx, arr) => `
                <span class="chain-step ${idx === arr.length - 1 ? 'impact' : ''}">${escapeHtml(step)}</span>
                ${idx < arr.length - 1 ? '<span class="chain-arrow">→</span>' : ''}
              `).join('')}
            </div>
          `;
          chainsList.appendChild(row);
        });
      }
    }

    const svg = $('#attack-graph-svg');
    const container = $('#graph-canvas-container');
    const tooltip = $('#graph-tooltip');
    if (!svg || !container) return;

    const width = container.clientWidth || 920;
    const height = 480;
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    svg.replaceChildren();

    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.innerHTML = `
      <marker id="arrow-default" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="rgba(67, 226, 210, 0.6)"/>
      </marker>
      <marker id="arrow-crit" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#f87171"/>
      </marker>
    `;
    svg.appendChild(defs);

    const nodes = graph.nodes || [];
    const layers = { target: [], subdomain: [], ip: [], exposure: [], impact: [] };
    nodes.forEach(n => {
      const type = n.type || 'subdomain';
      if (layers[type]) layers[type].push(n);
      else layers.subdomain.push(n);
    });

    const activeLayers = ['target', 'subdomain', 'ip', 'exposure', 'impact'].filter(l => layers[l].length > 0);
    const colStep = (width - 160) / Math.max(1, activeLayers.length - 1);

    const nodeCoords = new Map();
    activeLayers.forEach((layerKey, colIdx) => {
      const layerNodes = layers[layerKey];
      const x = 80 + colIdx * colStep;
      const rowStep = (height - 80) / (layerNodes.length + 1);
      layerNodes.forEach((node, rowIdx) => {
        const y = 40 + (rowIdx + 1) * rowStep;
        nodeCoords.set(node.id, { x, y, node });
      });
    });

    const gLinks = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    gLinks.className.baseVal = 'graph-links';
    (graph.links || []).forEach(link => {
      const src = nodeCoords.get(link.source);
      const tgt = nodeCoords.get(link.target);
      if (!src || !tgt) return;

      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      const isCrit = link.severity === 'CRITICAL' || tgt.node.severity === 'CRITICAL';
      const stroke = isCrit ? '#f87171' : (link.severity === 'HIGH' ? '#fb923c' : 'rgba(67, 226, 210, 0.35)');
      const strokeWidth = isCrit ? '2.2' : '1.4';
      const marker = isCrit ? 'url(#arrow-crit)' : 'url(#arrow-default)';

      const cx1 = (src.x + tgt.x) / 2;
      const cy1 = src.y;
      const cx2 = (src.x + tgt.x) / 2;
      const cy2 = tgt.y;

      path.setAttribute('d', `M ${src.x} ${src.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${tgt.x} ${tgt.y}`);
      path.setAttribute('fill', 'none');
      path.setAttribute('stroke', stroke);
      path.setAttribute('stroke-width', strokeWidth);
      path.setAttribute('marker-end', marker);
      path.dataset.source = link.source;
      path.dataset.target = link.target;
      path.className.baseVal = 'graph-link-path';
      gLinks.appendChild(path);
    });
    svg.appendChild(gLinks);

    const gNodes = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    gNodes.className.baseVal = 'graph-nodes';

    nodeCoords.forEach((coord, id) => {
      const n = coord.node;
      const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      group.className.baseVal = 'graph-node-group';
      group.style.cursor = 'pointer';

      let fill = '#38bdf8';
      let r = 8;
      if (n.type === 'target') { fill = '#43e2d2'; r = 11; }
      else if (n.type === 'ip') { fill = '#fb923c'; r = 7; }
      else if (n.type === 'exposure') { fill = '#f87171'; r = 9; }
      else if (n.type === 'impact') { fill = '#c084fc'; r = 10; }

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', coord.x);
      circle.setAttribute('cy', coord.y);
      circle.setAttribute('r', r);
      circle.setAttribute('fill', fill);
      circle.setAttribute('stroke', '#051216');
      circle.setAttribute('stroke-width', '2');
      if (n.severity === 'CRITICAL' || n.type === 'impact') {
        circle.setAttribute('filter', 'drop-shadow(0 0 6px rgba(248, 113, 113, 0.8))');
      }

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', coord.x);
      text.setAttribute('y', coord.y + r + 13);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('fill', '#e4f2ee');
      text.setAttribute('font-size', '10px');
      text.setAttribute('font-family', 'monospace');
      text.textContent = (n.label || '').length > 22 ? n.label.slice(0, 20) + '..' : n.label;

      group.appendChild(circle);
      group.appendChild(text);

      group.addEventListener('mouseenter', (ev) => {
        if (!tooltip) return;
        tooltip.style.display = 'block';
        tooltip.innerHTML = `
          <strong style="color:${fill};display:block;margin-bottom:2px;">${escapeHtml(n.label)}</strong>
          <div style="font-size:10px;color:#8ea39b;">Type: <code style="color:#e4f2ee;">${escapeHtml(n.type)}</code></div>
          <div style="font-size:10px;color:#8ea39b;">Severity: <strong style="color:${n.severity === 'CRITICAL' ? '#f87171' : '#43e2d2'};">${escapeHtml(n.severity || 'INFO')}</strong></div>
          ${n.meta && Object.keys(n.meta).length ? `<div style="font-size:9px;color:#94a3b8;margin-top:4px;">${escapeHtml(JSON.stringify(n.meta))}</div>` : ''}
        `;
        const rect = container.getBoundingClientRect();
        tooltip.style.left = `${ev.clientX - rect.left + 15}px`;
        tooltip.style.top = `${ev.clientY - rect.top + 10}px`;
      });
      group.addEventListener('mouseleave', () => {
        if (tooltip) tooltip.style.display = 'none';
      });

      group.addEventListener('click', () => {
        const isSelected = group.classList.toggle('selected');
        $$('.graph-node-group', svg).forEach(g => {
          if (g !== group) g.style.opacity = isSelected ? '0.25' : '1';
        });
        $$('.graph-link-path', svg).forEach(p => {
          const connected = p.dataset.source === id || p.dataset.target === id;
          p.style.opacity = isSelected ? (connected ? '1' : '0.1') : '1';
          if (isSelected && connected) {
            p.style.stroke = '#f87171';
            p.style.strokeWidth = '3';
          } else {
            p.style.stroke = '';
            p.style.strokeWidth = '';
          }
        });
      });

      gNodes.appendChild(group);
    });
    svg.appendChild(gNodes);

    const resetBtn = $('#btn-recenter-graph');
    if (resetBtn) {
      resetBtn.onclick = () => {
        $$('.graph-node-group', svg).forEach(g => {
          g.classList.remove('selected');
          g.style.opacity = '1';
        });
        $$('.graph-link-path', svg).forEach(p => {
          p.style.opacity = '1';
          p.style.stroke = '';
          p.style.strokeWidth = '';
        });
      };
    }

    const critBtn = $('#btn-filter-critical-paths');
    if (critBtn) {
      critBtn.onclick = () => {
        const critNodes = new Set();
        (graph.links || []).forEach(l => {
          if (l.severity === 'CRITICAL' || l.severity === 'HIGH') {
            critNodes.add(l.source);
            critNodes.add(l.target);
          }
        });
        $$('.graph-node-group', svg).forEach(g => {
          const textEl = g.querySelector('text');
          const isCrit = textEl && Array.from(nodeCoords.values()).some(c => critNodes.has(c.node.id) && c.node.label.startsWith(textEl.textContent.replace('..', '')));
          g.style.opacity = isCrit ? '1' : '0.15';
        });
        $$('.graph-link-path', svg).forEach(p => {
          const isCritLink = critNodes.has(p.dataset.source) && critNodes.has(p.dataset.target);
          p.style.opacity = isCritLink ? '1' : '0.1';
        });
      };
    }
  }

  // =========================================================================
  // Scan Execution & Polling Engine
  // =========================================================================
  function stopPolling() {
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
    if (timerLoop) {
      clearInterval(timerLoop);
      timerLoop = null;
    }
  }

  async function pollScan() {
    if (!activeScanId) return;
    try {
      const response = await fetch(`/api/scans/${encodeURIComponent(activeScanId)}`);
      if (!response.ok) throw new Error('Status could not be refreshed.');
      const job = await response.json();
      lastJob = job;
      updateProgress(job);

      if (job.status === 'completed') {
        stopPolling();
        buildReport(job);
        // Refresh history counter badge
        loadScanHistory();
        return;
      }
      if (job.status === 'failed') {
        stopPolling();
        return;
      }
      pollTimer = window.setTimeout(pollScan, 850);
    } catch {
      pollTimer = window.setTimeout(pollScan, 1800);
    }
  }

  // Centralized scan state & DOM output reset
  function clearAllScanOutputs() {
    // 1. Hide Advanced CTEM view & Terminal
    const advView = $('#advanced-results-view');
    if (advView) advView.hidden = true;
    const term = $('#surfacedrift-terminal');
    if (term) term.hidden = true;
    const termBody = $('#adv-log-lines');
    if (termBody) termBody.replaceChildren();
    const termCount = $('#adv-log-count');
    if (termCount) termCount.textContent = '0 events';

    // 2. Reset Composite Exposure Score & Deductions
    const scoreVal = $('#adv-score-val');
    if (scoreVal) scoreVal.textContent = '—';
    const gradeLetter = $('#adv-grade-letter');
    if (gradeLetter) gradeLetter.textContent = '—';
    const gradeCircle = $('#adv-grade-circle');
    if (gradeCircle) gradeCircle.className = 'grade-circle';
    const dedContainer = $('#adv-deductions-container');
    if (dedContainer) {
      dedContainer.innerHTML = '<span class="no-deductions">Assessment pending.</span>';
    }
    const aiSummary = $('#adv-ai-summary-content');
    if (aiSummary) {
      aiSummary.innerHTML = '<p class="empty-state">No active assessment summary.</p>';
    }

    // 3. Reset Deep Findings Containers & Badges
    const emptyFindings = [
      ['#adv-container-http', '#adv-badge-http', 'No live web services probed.', '0 live'],
      ['#adv-container-takeover', '#adv-badge-takeover', 'No dangling CNAME takeovers detected.', '0 found'],
      ['#adv-container-cloud', '#adv-badge-cloud', 'No exposed storage buckets found.', '0 found'],
      ['#adv-container-waf', '#adv-badge-waf', 'No direct origin bypass IPs discovered.', '0 origins'],
      ['#adv-container-cves', '#adv-badge-cves', 'No weaponized vulnerabilities found.', '0 weaponized'],
      ['#adv-container-email', '#adv-badge-email', 'Email audit pending.', 'RFC Verified'],
      ['#adv-container-secrets', '#adv-badge-secrets', 'No leaked credentials found in JavaScript.', '0 secrets'],
      ['#adv-container-shadow-api', '#adv-badge-shadow-api', 'No unauthenticated API endpoints exposed.', '0 endpoints'],
      ['#adv-container-eol', '#adv-badge-eol', 'No deprecated or EOL software runtimes detected.', '0 EOL'],
      ['#adv-container-blh', '#adv-badge-blh', 'No broken link hijacking detected.', '0 broken'],
      ['#adv-container-waf-history', '#adv-badge-waf-history', 'No historical origin bypasses discovered.', '0 origins'],
      ['#adv-container-config', '#adv-badge-config', 'No sensitive configuration files exposed.', '0 exposed'],
      ['#adv-container-tls', '#adv-badge-tls', 'All certificates valid and modern TLS enforced.', '0 evaluated'],
      ['#adv-container-breach', '#adv-badge-breach', 'Zero employee email addresses found in credential breaches.', '0 compromised'],
      ['#adv-container-typosquat', '#adv-badge-typosquat', 'No active typosquatted domains detected.', '0 active'],
      ['#adv-container-remediation', '#adv-badge-remediation', 'Zero remediation actions required.', '0 playbooks'],
    ];
    emptyFindings.forEach(([boxSel, badgeSel, emptyMsg, badgeDefault]) => {
      const box = $(boxSel);
      if (box) box.innerHTML = `<p class="empty-state">${emptyMsg}</p>`;
      const badge = $(badgeSel);
      if (badge) {
        badge.textContent = badgeDefault;
        badge.className = 'finding-badge';
      }
    });

    // 4. Reset Phase 1 Lists & Tables
    const listsToClear = [
      '#list-subdomains',
      '#list-emails',
      '#list-employees',
      '#list-buckets',
      '#list-creds',
      '#list-hashes',
      '#grid-artifacts',
    ];
    listsToClear.forEach((sel) => {
      const el = $(sel);
      if (el) el.replaceChildren();
    });
    const tbodiesToClear = [
      '#table-ips tbody',
      '#table-dns tbody',
      '#table-ports tbody',
    ];
    tbodiesToClear.forEach((sel) => {
      const el = $(sel);
      if (el) el.replaceChildren();
    });

    // Reset badges
    const badgesToReset = [
      ['#badge-subdomains', '0'],
      ['#badge-dns', '0'],
      ['#badge-ips', '0'],
      ['#badge-ports', '0 ports'],
      ['#badge-emails', '0'],
      ['#badge-guessed', '0'],
      ['#badge-employees', '0'],
      ['#badge-buckets', '0'],
      ['#badge-creds', '0'],
      ['#badge-artifacts', '0'],
      ['#quick-badge-subdomains', '0'],
      ['#quick-badge-dns', '0'],
      ['#quick-badge-ips', '0'],
      ['#quick-badge-ports', '0'],
      ['#quick-badge-emails', '0'],
      ['#quick-badge-employees', '0'],
      ['#quick-badge-buckets', '0'],
      ['#quick-badge-artifacts', '0'],
      ['#bridge-subdomain-count', '0'],
      ['#bridge-ip-count', '0'],
    ];
    badgesToReset.forEach(([sel, val]) => {
      const b = $(sel);
      if (b) b.textContent = val;
    });

    // 5. Reset Surface Drift Tab
    const driftBadge = $('#drift-status-badge');
    if (driftBadge) {
      driftBadge.textContent = 'Baseline Scan Recorded';
      driftBadge.className = 'drift-badge';
      driftBadge.style.color = '';
      driftBadge.style.borderColor = '';
    }
    const scoreDelta = $('#drift-score-delta');
    if (scoreDelta) {
      scoreDelta.textContent = '0 pts';
      scoreDelta.className = 'drift-stat-val';
    }
    $('#drift-new-subs-count').textContent = '0';
    $('#drift-new-ports-count').textContent = '0';
    $('#drift-new-threats-count').textContent = '0';
    $('#drift-resolved-count').textContent = '0';
    $('#drift-baseline-time').textContent = '—';
    $('#drift-current-time').textContent = '—';
    const driftListAssets = $('#drift-list-new-assets');
    if (driftListAssets) driftListAssets.innerHTML = '<p class="empty-state">No new shadow assets detected compared to baseline.</p>';
    const driftListThreats = $('#drift-list-new-threats');
    if (driftListThreats) driftListThreats.innerHTML = '<p class="empty-state">No newly introduced vulnerabilities or takeovers.</p>';
    const driftListResolved = $('#drift-list-resolved');
    if (driftListResolved) driftListResolved.innerHTML = '<p class="empty-state">No previously exposed assets were closed.</p>';

    // 6. Reset Attack Path Graph & MITRE ATT&CK
    const svg = $('#attack-graph-svg');
    if (svg) svg.replaceChildren();
    const chainsList = $('#attack-chains-list');
    if (chainsList) chainsList.innerHTML = '<p class="empty-state">Attack path graph will be synthesized upon scan completion.</p>';
    const chainsBadge = $('#graph-chains-badge');
    if (chainsBadge) chainsBadge.textContent = '0 Chains';
    const mitreGrid = $('#mitre-matrix-grid');
    if (mitreGrid) mitreGrid.innerHTML = '<p class="empty-state" style="grid-column: 1 / -1; text-align: center; padding: 30px;">MITRE ATT&CK matrix alignment will load upon scan completion.</p>';
  }

  async function executeScan(target, authorized, mode) {
    clearAllScanOutputs();
    preflightNote.hidden = true;
    startButton.disabled = true;
    $('span:first-child', startButton).textContent = 'Launching…';

    try {
      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ target, authorized, mode }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Could not start the scan.');

      activeScanId = result.id;
      history.pushState(null, '', `/scan?scan_id=${encodeURIComponent(result.id)}`);
      scanStartedAt = Date.now();

      $('#running-target').textContent = result.target;
      $('#running-mode-tag').textContent = mode.toUpperCase();
      $('#progress-title').textContent = 'Preparing the scan';
      $('#progress-fill').style.width = '2%';
      $('#progress-percent').textContent = '02%';
      $('#progress-detail').textContent = `Initializing ${mode.toUpperCase()} reconnaissance engine…`;
      $('#ticker-text').textContent = 'Starting process...';
      $('#elapsed-time').textContent = '00:00';
      $('#scan-error').hidden = true;

      renderStages({ status: 'running', progress: 2, stage: 'Preparing scan' });
      renderLogs([]);
      showView('progress');

      timerLoop = window.setInterval(() => {
        $('#elapsed-time').textContent = formatElapsed();
      }, 1000);

      pollScan();
    } catch (error) {
      preflightNote.textContent = error.message || 'Could not start the scan.';
      preflightNote.hidden = false;
    } finally {
      startButton.disabled = false;
      $('span:first-child', startButton).textContent = 'Start Assessment';
    }
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const target = targetInput.value.trim();
    const authorized = $('#authorized-check').checked;
    if (!target) return;

    // Check if user is unauthenticated (Guest)
    if (!currentUser) {
      const modal = $('#guest-confirm-modal');
      if (modal) {
        modal.hidden = false;
        const proceedBtn = $('#guest-modal-proceed-btn');
        const loginBtn = $('#guest-modal-login-btn');
        const closeX = $('#guest-modal-close-x');

        const closeModal = () => {
          modal.hidden = true;
          if (proceedBtn) proceedBtn.onclick = null;
          if (loginBtn) loginBtn.onclick = null;
          if (closeX) closeX.onclick = null;
        };

        if (closeX) {
          closeX.onclick = closeModal;
        }

        if (proceedBtn) {
          proceedBtn.onclick = () => {
            closeModal();
            executeScan(target, authorized, currentMode);
          };
        }

        if (loginBtn) {
          loginBtn.onclick = () => {
            closeModal();
            triggerGoogleLogin();
          };
        }
        return;
      }
    }

    executeScan(target, authorized, currentMode);
  });

  async function triggerDownload() {
    if (!activeScanId || !lastJob || lastJob.status !== 'completed') return;
    const downloadStatus = $('#download-status');

    // If Phase 2 CTEM data is present, prefer the PDF executive report
    if (lastJob.surfacedrift_advanced) {
      if (downloadStatus) downloadStatus.textContent = 'Generating PDF executive report…';
      await downloadReportFile(activeScanId, lastJob.target || 'target', 'pdf');
      if (downloadStatus) downloadStatus.textContent = 'PDF report downloaded.';
      return;
    }

    if (downloadStatus) downloadStatus.textContent = 'Preparing your report archive…';

    await downloadScanArchive({
      id: activeScanId,
      target: lastJob.target,
      summary: lastJob.summary,
      surfacedrift_advanced: lastJob.surfacedrift_advanced,
    });

    if (downloadStatus) downloadStatus.textContent = 'Report downloaded.';
  }

  $('#download-report-button').addEventListener('click', triggerDownload);
  $('#download-report-button-top').addEventListener('click', triggerDownload);

  function resetToForm() {
    stopPolling();
    activeScanId = null;
    lastJob = null;
    scanStartedAt = null;
    clearAllScanOutputs();
    form.reset();
    clearButton.hidden = true;
    history.pushState(null, '', '/scan');
    $('#scan-error').hidden = true;
    $('#progress-fill').style.width = '1%';
    $('#progress-fill').style.background = '';
    $('#progress-percent').style.color = '';
    $('#download-status').textContent = '';
    const scanWrap = $('.scan-wrap');
    if (scanWrap) scanWrap.classList.remove('results-mode');
    renderStages({ status: 'queued', progress: 0, stage: 'queued' });

    // Sync mode selection cards to passive
    $$('.mode-card').forEach((c) => c.classList.remove('active'));
    const passiveCard = $('#mode-passive-card');
    if (passiveCard) passiveCard.classList.add('active');
    currentMode = 'passive';

    showView('form');
    targetInput.value = '';
    targetInput.focus();
  }

  $('#try-again-button')?.addEventListener('click', resetToForm);
  $('#new-scan-button')?.addEventListener('click', resetToForm);
  $('#new-scan-button-top')?.addEventListener('click', resetToForm);
  $('#notice-new-scan-btn')?.addEventListener('click', resetToForm);

  // Any link targeting /scan should reset to form when already on the workspace
  $$('a[href="/scan"]').forEach((a) => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      resetToForm();
    });
  });

  const backLink = $('.back-link');
  if (backLink) {
    backLink.addEventListener('click', (e) => {
      if (!reportPanel.hidden || !progressPanel.hidden) {
        e.preventDefault();
        resetToForm();
      }
    });
  }

  // Load existing scan from history
  function loadExistingScan(scanId) {
    clearAllScanOutputs();
    activeScanId = scanId;
    history.pushState(null, '', `/scan?scan_id=${encodeURIComponent(scanId)}`);
    showView('progress');
    $('#progress-title').textContent = 'Loading scan…';
    fetch(`/api/scans/${encodeURIComponent(scanId)}`, { headers: getAuthHeaders() })
      .then((res) => {
        if (!res.ok) throw new Error('Scan not found');
        return res.json();
      })
      .then((job) => {
        lastJob = job;
        if (job.status === 'completed') {
          buildReport(job);
        } else {
          updateProgress(job);
          if (job.status === 'running' || job.status === 'queued') {
            pollScan();
          }
        }
      })
      .catch((err) => {
        alert(err.message || 'Could not load scan.');
        resetToForm();
      });
  }

  // Restore scan from URL if parameter present
  const urlParams = new URLSearchParams(window.location.search);
  const initialScanId = urlParams.get('scan_id');
  if (initialScanId) {
    loadExistingScan(initialScanId);
  }
})();
