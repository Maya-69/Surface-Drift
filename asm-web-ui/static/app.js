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

  async function checkAuth() {
    try {
      const res = await fetch('/api/auth/me');
      const data = await res.json();
      if (data.authenticated && data.user) {
        setLoggedInUser(data.user, data.total_scans);
      } else {
        setLoggedOutUser();
      }
    } catch {
      setLoggedOutUser();
    }
  }

  function setLoggedInUser(user, totalScans) {
    currentUser = user;
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
  }

  function setLoggedOutUser() {
    currentUser = null;
    const loginBtn = $('#google-login-btn');
    const userPill = $('#user-pill');
    if (loginBtn) loginBtn.hidden = false;
    if (userPill) userPill.hidden = true;
    $('#user-dropdown').hidden = true;
  }

  // Google Sign-In setup
  fetch('/api/auth/config')
    .then((r) => r.json())
    .then((cfg) => {
      if (cfg.google_client_id && window.google && window.google.accounts) {
        window.google.accounts.id.initialize({
          client_id: cfg.google_client_id,
          callback: handleGoogleCredentialResponse,
        });
      }
    })
    .catch(() => {});

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
        loadScanHistory();
      }
    } catch {
      alert('Could not authenticate with Google.');
    }
  }

  const googleLoginBtn = $('#google-login-btn');
  if (googleLoginBtn) {
    googleLoginBtn.addEventListener('click', async () => {
      // If official GIS is loaded with client ID, open prompt
      if (window.google && window.google.accounts && window.google.accounts.id.prompt) {
        try {
          window.google.accounts.id.prompt();
          return;
        } catch {}
      }
      // Instant Seamless Sign-In for demo and local execution
      const email = prompt('Sign in with your Google email:', 'sawantmayuresh2006@gmail.com');
      if (!email) return;
      const name = prompt('Display Name:', 'Maya') || 'Maya';
      try {
        const res = await fetch('/api/auth/google', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ demo: true, email: email.trim(), name: name.trim() }),
        });
        const data = await res.json();
        if (data.ok && data.user) {
          setLoggedInUser(data.user);
          loadScanHistory();
        }
      } catch (err) {
        alert('Authentication error: ' + err.message);
      }
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

  async function loadScanHistory() {
    const listEl = $('#history-list');
    if (!listEl) return;
    listEl.innerHTML = '<p class="empty-state">Loading scan history…</p>';
    try {
      const res = await fetch('/api/scans/history');
      const historyData = await res.json();
      const badge = $('#history-badge');
      if (badge) badge.textContent = historyData.length;

      if (!historyData.length) {
        listEl.innerHTML = '<p class="empty-state"><span>◇</span>No scans recorded yet.<br />Run an assessment to build your history.</p>';
        return;
      }

      listEl.replaceChildren();
      historyData.forEach((item) => {
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
            ${item.status === 'completed' ? `<a class="btn-history-action" href="/api/scans/${item.id}/download">Download ZIP ↓</a>` : ''}
            <button class="btn-history-action btn-delete-scan" data-id="${item.id}" type="button">Delete</button>
          </div>
        `;

        card.querySelector('.btn-view-results').onclick = () => {
          closeHistory();
          loadExistingScan(item.id);
        };

        card.querySelector('.btn-delete-scan').onclick = async () => {
          if (confirm(`Delete scan record for ${item.target}?`)) {
            await fetch(`/api/scans/${item.id}`, { method: 'DELETE' });
            loadScanHistory();
          }
        };

        listEl.appendChild(card);
      });
    } catch {
      listEl.innerHTML = '<p class="empty-state" style="color:#eaa58c">Could not load scan history.</p>';
    }
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

        let completed = false;
        try {
          const resp = await fetch(`/api/scans/${encodeURIComponent(job.id)}/continue-surfacedrift-stream`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ categories }),
          });

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
                  renderAdvancedResults(event.advanced, job.id);
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
            appendAdvLog(`[*] Streaming connection closed, falling back to direct assessment...`);
            const fallbackResp = await fetch(`/api/scans/${encodeURIComponent(job.id)}/continue-surfacedrift`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ categories }),
            });
            if (!fallbackResp.ok) {
              const err = await fallbackResp.json().catch(() => ({}));
              throw new Error(err.detail || 'SurfaceDrift assessment failed.');
            }
            const fallbackData = await fallbackResp.json();
            if (fallbackData.advanced && fallbackData.advanced.logs) {
              fallbackData.advanced.logs.forEach(appendAdvLog);
            }
            renderAdvancedResults(fallbackData.advanced, job.id);
            launchBtn.innerHTML = '<span>Re-run SurfaceDrift Analysis</span><span class="button-arrow" aria-hidden="true">⚡</span>';
          }
        } finally {
          launchBtn.disabled = false;
          statusBox.hidden = true;
        }
      };
    }
  }

  function renderAdvancedResults(adv, scanId) {
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

    // 4. Combined Download All Link
    const combinedBtn = $('#btn-download-combined-all');
    if (combinedBtn) {
      combinedBtn.href = `/api/scans/${encodeURIComponent(scanId)}/download-combined`;
      combinedBtn.setAttribute('download', `surfacedrift-complete-${scanId}.zip`);
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

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const target = targetInput.value.trim();
    const authorized = $('#authorized-check').checked;
    if (!target) return;

    preflightNote.hidden = true;
    startButton.disabled = true;
    $('span:first-child', startButton).textContent = 'Launching…';

    try {
      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, authorized, mode: currentMode }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Could not start the scan.');

      activeScanId = result.id;
      history.pushState(null, '', `/scan?scan_id=${encodeURIComponent(result.id)}`);
      scanStartedAt = Date.now();

      $('#running-target').textContent = result.target;
      $('#running-mode-tag').textContent = currentMode.toUpperCase();
      $('#progress-title').textContent = 'Preparing the scan';
      $('#progress-fill').style.width = '2%';
      $('#progress-percent').textContent = '02%';
      $('#progress-detail').textContent = `Initializing ${currentMode.toUpperCase()} reconnaissance engine…`;
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
  });

  function triggerDownload() {
    if (!activeScanId || !lastJob || lastJob.status !== 'completed') return;
    $('#download-status').textContent = 'Your download is starting…';
    window.location.assign(`/api/scans/${encodeURIComponent(activeScanId)}/download`);
    window.setTimeout(() => {
      $('#download-status').textContent = 'Report download requested.';
    }, 900);
  }

  $('#download-report-button').addEventListener('click', triggerDownload);
  $('#download-report-button-top').addEventListener('click', triggerDownload);

  function resetToForm() {
    stopPolling();
    activeScanId = null;
    lastJob = null;
    scanStartedAt = null;
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
    activeScanId = scanId;
    history.pushState(null, '', `/scan?scan_id=${encodeURIComponent(scanId)}`);
    showView('progress');
    $('#progress-title').textContent = 'Loading scan…';
    fetch(`/api/scans/${encodeURIComponent(scanId)}`)
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
