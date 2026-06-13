// Navigation
document.querySelectorAll('.nav-item[data-page]').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    const page = item.dataset.page;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const pageMap = {
      'dashboard': 'page-dashboard', 'alerts': 'page-alerts',
      'incidents': 'page-incidents', 'logs': 'page-logs',
      'threat-intel': 'page-executive', 'users': 'page-executive',
      'settings': 'page-dashboard'
    };
    document.getElementById(pageMap[page] || 'page-dashboard').classList.add('active');
  });
});

// Chart defaults
Chart.defaults.color = '#64748b';
Chart.defaults.borderColor = '#1e293b';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;
Chart.defaults.plugins.legend.display = false;

// Sparklines in stat cards
function drawSparkSVG(containerId, data, color) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const bars = data.map((v, i) => {
    const h = 4 + v * 20;
    return `<div style="width:3px;height:${h}px;background:${color};border-radius:1px;opacity:${0.4 + v * 0.6}"></div>`;
  }).join('');
  el.innerHTML = `<div style="display:flex;align-items:flex-end;gap:2px;height:24px">${bars}</div>`;
}
drawSparkSVG('spark-alerts', [.3,.5,.4,.7,.6,.8,.9,.7], '#ef4444');
drawSparkSVG('spark-ingest', [.4,.5,.6,.5,.7,.6,.8,.7], '#3b82f6');
drawSparkSVG('spark-blocked', [.5,.6,.7,.8,.6,.7,.9,.8], '#f97316');
drawSparkSVG('spark-anomalies', [.3,.4,.3,.5,.4,.3,.5,.4], '#8b5cf6');
drawSparkSVG('spark-incidents', [.6,.5,.7,.6,.5,.4,.5,.4], '#06b6d4');
drawSparkSVG('spark-mttr', [.8,.7,.6,.5,.6,.5,.4,.3], '#22c55e');

// Network Throughput Chart
new Chart(document.getElementById('chart-throughput'), {
  type: 'line',
  data: {
    labels: Array.from({length: 60}, (_, i) => ''),
    datasets: [{
      label: 'Inbound',
      data: Array.from({length: 60}, () => 60 + Math.random() * 50),
      borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)',
      fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0
    }, {
      label: 'Outbound',
      data: Array.from({length: 60}, () => 20 + Math.random() * 25),
      borderColor: '#f97316', backgroundColor: 'rgba(249,115,22,0.1)',
      fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    scales: { x: { display: false }, y: { display: true, grid: { color: '#1e293b' }, ticks: { callback: v => v } } },
    plugins: { tooltip: { mode: 'index', intersect: false } }
  }
});

// Incident Distribution Donut
new Chart(document.getElementById('chart-incidents-donut'), {
  type: 'doughnut',
  data: {
    labels: ['Policy Violations', 'Malware', 'Intrusions', 'Anomalies'],
    datasets: [{ data: [40, 32, 20, 8], backgroundColor: ['#06b6d4', '#8b5cf6', '#f97316', '#22c55e'], borderWidth: 0 }]
  },
  options: {
    responsive: true, maintainAspectRatio: false, cutout: '65%',
    plugins: { legend: { display: false } }
  }
});

// Auth Failures Heatmap
const heatmapEl = document.getElementById('heatmap-auth');
const days = ['M', 'T', 'W', 'T', 'F', 'S', 'S'];
const hours = Array.from({length: 24}, (_, i) => i);
const heatColors = ['#0a0e17', '#1a1a2e', '#1e3a5f', '#2563eb', '#f97316', '#ef4444'];

days.forEach((day, di) => {
  const label = document.createElement('div');
  label.className = 'heatmap-label';
  label.textContent = day;
  heatmapEl.appendChild(label);
  hours.forEach(h => {
    const cell = document.createElement('div');
    cell.className = 'heatmap-cell';
    const intensity = Math.random();
    const ci = Math.min(Math.floor(intensity * heatColors.length), heatColors.length - 1);
    cell.style.background = heatColors[ci];
    cell.title = `${day} ${String(h).padStart(2,'0')}:00 — ${Math.floor(intensity * 500)} fails`;
    heatmapEl.appendChild(cell);
  });
});

// Events Table
const tactics = ['Lateral Movement', 'C2 Comms', 'Exfiltration', 'Access', 'Brute Force', 'Exploit', 'Scanning', 'Discovery'];
const actions = ['Blocked', 'Allowed', 'Flagged'];
const sevs = ['CRIT', 'HIGH', 'MED', 'LOW'];
const sevClasses = { CRIT: 'crit', HIGH: 'high', MED: 'med', LOW: 'low' };
const actionClasses = { Blocked: 'action-blocked', Allowed: 'action-allowed', Flagged: 'action-flagged' };
const protos = ['TCP', 'UDP'];

function randomIP() { return `${Math.floor(Math.random()*223+1)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`; }
function randomPort() { return Math.floor(Math.random() * 65535); }

function generateEventRows(tbodyId, count) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  tbody.innerHTML = '';
  const srcIPs = ['192.168.1.104', '10.0.0.12', '10.0.0.45', '192.168.1.5', '45.33.22.11', '10.0.2.55', '172.16.0.14', '10.0.3.22', '192.168.1.104'];
  const dstIPs = ['10.0.0.5', '8.8.8.8', '198.51.100.23', '10.0.1.10', '10.0.5.12', '10.0.2.1', '10.0.0.100', '10.0.3.255', '10.0.0.5'];
  for (let i = 0; i < count; i++) {
    const h = 14 - Math.floor(i * 0.3);
    const m = Math.floor(Math.random() * 60);
    const s = Math.floor(Math.random() * 60);
    const time = `${h}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}.${String(Math.floor(Math.random()*999)).padStart(3,'0')}`;
    const sev = sevs[i % 4];
    const src = srcIPs[i % srcIPs.length];
    const dst = dstIPs[i % dstIPs.length];
    const sp = [44321, 53422, 12345, 49221, 33211, 55431, 60123, 44322, 50012][i % 9];
    const dp = [445, 53, 443, 3389, 22, 80, 8080, 137, 445][i % 9];
    const proto = protos[i % 2];
    const tactic = tactics[i % tactics.length];
    const action = actions[i % 3];
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${time}</td><td><span class="sev-badge ${sevClasses[sev]}">${sev}</span></td><td>${src}:${sp}</td><td>${dst}:${dp}</td><td>${proto}</td><td>${tactic}</td><td class="${actionClasses[action]}">${action}</td><td><div class="investigate-btns"><button title="Search"><i class="fas fa-search"></i></button><button title="Investigate"><i class="fas fa-arrow-right"></i></button></div></td>`;
    tbody.appendChild(tr);
  }
}
generateEventRows('events-tbody', 10);
generateEventRows('alerts-tbody', 10);

// Top Blocked Subnets
const subnets = [
  { name: '45.33.0.0/16', count: 12450, color: '#ef4444' },
  { name: '198.51.100.0/24', count: 8320, color: '#f97316' },
  { name: '203.0.113.0/24', count: 5104, color: '#eab308' },
  { name: '10.0.5.0/24 (Int)', count: 2401, color: '#22c55e' },
  { name: '192.0.2.0/24', count: 940, color: '#ef4444' }
];
const subnetList = document.getElementById('subnet-list');
subnets.forEach(s => {
  const pct = (s.count / subnets[0].count) * 100;
  subnetList.innerHTML += `<div class="subnet-item"><div class="subnet-row"><span class="subnet-name">${s.name}</span><span class="subnet-count">${s.count.toLocaleString()}</span></div><div class="subnet-bar" style="background:${s.color};width:${pct}%"></div></div>`;
});

// Detection Timelines
const detections = [
  { name: 'Brute Force Camp.', color: '#f97316', width: 45 },
  { name: 'Port Scan Sweep', color: '#3b82f6', width: 20 },
  { name: 'Data Exfil Attempt', color: '#ef4444', width: 15 },
  { name: 'Malware Beacon', color: '#8b5cf6', width: 60 }
];
const tlEl = document.getElementById('detection-timelines');
detections.forEach(d => {
  tlEl.innerHTML += `<div class="tl-bar-item"><div class="tl-bar-label">${d.name}</div><div class="tl-bar" style="background:${d.color};width:${d.width}%"></div></div>`;
});

// Investigation Timeline Chart (Alerts page)
const invCtx = document.getElementById('chart-investigation');
if (invCtx) {
  new Chart(invCtx, {
    type: 'line',
    data: {
      labels: Array.from({length: 24}, (_, i) => `${i}:00`),
      datasets: [{
        data: Array.from({length: 24}, () => Math.floor(Math.random() * 30 + 5)),
        borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)',
        fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0
      }]
    },
    options: { responsive: true, maintainAspectRatio: false, scales: { x: { grid: { display: false } }, y: { grid: { color: '#1e293b' } } } }
  });
}

// Log Volume Chart
const logCtx = document.getElementById('chart-log-volume');
if (logCtx) {
  new Chart(logCtx, {
    type: 'bar',
    data: {
      labels: Array.from({length: 48}, (_, i) => ''),
      datasets: [{
        data: Array.from({length: 48}, () => Math.floor(Math.random() * 100 + 10)),
        backgroundColor: Array.from({length: 48}, () => {
          const v = Math.random();
          return v > 0.85 ? '#ef4444' : v > 0.7 ? '#f97316' : '#3b82f6';
        }),
        borderRadius: 2, barPercentage: 0.8
      }]
    },
    options: { responsive: true, maintainAspectRatio: false, scales: { x: { display: false }, y: { display: false } } }
  });
}

// Logs table
function generateLogRows() {
  const tbody = document.getElementById('logs-tbody');
  if (!tbody) return;
  const types = ['Authentication', 'Firewall', 'DNS Query', 'Process Start', 'File Access', 'Network Flow'];
  const sources = ['DC01.corp', 'FW-Edge-01', 'WS-PC0142', 'SRV-DB-01', 'proxy-01'];
  for (let i = 0; i < 15; i++) {
    const tr = document.createElement('tr');
    const sev = sevs[i % 4];
    const action = actions[i % 3];
    tr.innerHTML = `<td>2024-01-15 ${8 + Math.floor(i / 4)}:${String(Math.floor(Math.random()*60)).padStart(2,'0')}:${String(Math.floor(Math.random()*60)).padStart(2,'0')}</td><td>${sources[i % sources.length]}</td><td>${types[i % types.length]}</td><td class="${actionClasses[action]}">${action}</td><td><span class="sev-badge ${sevClasses[sev]}">${sev}</span></td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">Event details for ${types[i % types.length].toLowerCase()} event</td>`;
    tbody.appendChild(tr);
  }
}
generateLogRows();

// Executive - Risk Gauge
const gaugeCtx = document.getElementById('chart-risk-gauge');
if (gaugeCtx) {
  new Chart(gaugeCtx, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [75, 25],
        backgroundColor: ['#f97316', '#1e293b'],
        borderWidth: 0, circumference: 270, rotation: 225
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '78%',
      plugins: { legend: { display: false }, tooltip: { enabled: false } }
    }
  });
}

// Executive Volume Trend
const execCtx = document.getElementById('chart-exec-volume');
if (execCtx) {
  new Chart(execCtx, {
    type: 'bar',
    data: {
      labels: Array.from({length: 30}, (_, i) => i + 1),
      datasets: [{
        data: Array.from({length: 30}, () => Math.floor(Math.random() * 60 + 10)),
        backgroundColor: Array.from({length: 30}, () => {
          const v = Math.random();
          return v > 0.8 ? '#ef4444' : '#3b82f6';
        }),
        borderRadius: 3, barPercentage: 0.7
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: { x: { grid: { display: false } }, y: { grid: { color: '#1e293b' }, beginAtZero: true } }
    }
  });
}

// Category bars (Executive)
const categories = [
  { name: 'Malware', count: 847, pct: 85, color: '#ef4444' },
  { name: 'Phishing', count: 623, pct: 62, color: '#f97316' },
  { name: 'Data Breach', count: 412, pct: 41, color: '#eab308' },
  { name: 'DDoS', count: 289, pct: 29, color: '#3b82f6' },
  { name: 'Insider Threat', count: 156, pct: 16, color: '#8b5cf6' }
];
const catEl = document.getElementById('category-bars');
if (catEl) {
  categories.forEach(c => {
    catEl.innerHTML += `<div class="cat-item"><div class="cat-header"><span>${c.name}</span><span>${c.count}</span></div><div class="cat-bar"><div class="cat-fill" style="width:${c.pct}%;background:${c.color}"></div></div></div>`;
  });
}

// Compliance Grid
const compItems = [
  { name: 'PCI DSS', score: '92%', color: '#22c55e', status: 'Compliant' },
  { name: 'HIPAA', score: '87%', color: '#22c55e', status: 'Compliant' },
  { name: 'SOC 2', score: '78%', color: '#eab308', status: 'Partial' },
  { name: 'NIST CSF', score: '94%', color: '#22c55e', status: 'Compliant' },
  { name: 'ISO 27001', score: '85%', color: '#22c55e', status: 'Compliant' },
  { name: 'GDPR', score: '91%', color: '#22c55e', status: 'Compliant' }
];
const compEl = document.getElementById('compliance-grid');
if (compEl) {
  compItems.forEach(c => {
    compEl.innerHTML += `<div class="compliance-item"><div class="comp-name">${c.name}</div><div class="comp-score" style="color:${c.color}">${c.score}</div><div class="comp-status" style="color:${c.color}">${c.status}</div></div>`;
  });
}

// Tab clicks
document.querySelectorAll('.tab-group .tab, .incident-tabs .tab').forEach(tab => {
  tab.addEventListener('click', () => {
    tab.parentElement.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
  });
});
