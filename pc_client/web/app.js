// ============= 状态 =============
let TOKEN = null;
let WS = null;
let CHARTS = {};
let LAST_UPLOAD = null;

const $ = id => document.getElementById(id);

// ============= 工具 =============
async function api(path, opts={}) {
  opts.headers = opts.headers || {};
  if (TOKEN) opts.headers['X-Auth-Token'] = TOKEN;
  if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== 'string') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({detail: res.statusText}));
    throw new Error(err.detail || res.statusText);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.blob();
}

function logLine(msg, cls='log-info') {
  const box = $('logBox');
  const ts = new Date().toLocaleTimeString();
  box.innerHTML += `<span class="${cls}">[${ts}] ${msg}</span>\n`;
  box.scrollTop = box.scrollHeight;
}

function showModal(title, body, onOK, withInput=false) {
  $('modalTitle').textContent = title;
  $('modalBody').textContent = body;
  $('modalInput').classList.toggle('hidden', !withInput);
  $('modalInput').value = '';
  $('modal').classList.remove('hidden');
  $('modalOK').onclick = () => {
    if (onOK) onOK($('modalInput').value);
    $('modal').classList.add('hidden');
  };
  $('modalCancel').onclick = () => $('modal').classList.add('hidden');
}

// ============= 登录 =============
async function checkLoginStatus() {
  try {
    const s = await fetch('/api/status').then(r => r.json());
    $('loginHint').textContent = s.login_initialized ? '' : '(首次登录请设置密码)';
  } catch(e) {}
}

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').textContent = '';
  const pwd = $('loginPwd').value;
  if (pwd.length < 4) { $('loginError').textContent = '密码至少 4 位'; return; }
  try {
    const r = await fetch('/api/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: pwd})
    }).then(async res => {
      if (!res.ok) throw new Error((await res.json()).detail || '登录失败');
      return res.json();
    });
    TOKEN = r.token;
    $('loginPage').classList.add('hidden');
    $('dashboard').classList.remove('hidden');
    if (r.first_time) logLine('首次登录, 已为您设置该密码', 'log-ok');
    logLine('登录成功', 'log-ok');
    initDashboard();
  } catch (err) {
    $('loginError').textContent = err.message;
  }
});

$('btnLogout').addEventListener('click', async () => {
  try { await api('/api/logout', {method: 'POST'}); } catch(e) {}
  TOKEN = null;
  if (WS) { WS.close(); WS = null; }
  $('dashboard').classList.add('hidden');
  $('loginPage').classList.remove('hidden');
  $('loginPwd').value = '';
});

// ============= Dashboard 初始化 =============
function initDashboard() {
  initCharts();
  connectWS();
  refreshStatus();
  setInterval(refreshStatus, 5000);
}

function initCharts() {
  CHARTS.thr = echarts.init($('chartThroughput'));
  CHARTS.thr.setOption({
    title: {text: '传输吞吐率 (Mbps)', textStyle:{color:'#e6ecf7', fontSize:13}},
    grid: {top:40, left:50, right:20, bottom:30},
    xAxis: {type:'category', data:[], axisLabel:{color:'#97a4c0', fontSize:10, rotate:45}},
    yAxis: {type:'value', axisLabel:{color:'#97a4c0'}, splitLine:{lineStyle:{color:'#2b3a5e'}}},
    tooltip: {trigger:'axis'},
    series: [{type:'line', smooth:true, data:[],
              lineStyle:{color:'#00e2c0'},
              areaStyle:{color:'rgba(0,226,192,0.15)'},
              symbolSize:6}]
  });

  CHARTS.lat = echarts.init($('chartLatency'));
  CHARTS.lat.setOption({
    title: {text: '解密延迟 (ms)', textStyle:{color:'#e6ecf7', fontSize:13}},
    grid: {top:40, left:50, right:20, bottom:30},
    xAxis: {type:'category', data:[], axisLabel:{color:'#97a4c0', fontSize:10, rotate:45}},
    yAxis: {type:'value', axisLabel:{color:'#97a4c0'}, splitLine:{lineStyle:{color:'#2b3a5e'}}},
    tooltip: {trigger:'axis'},
    series: [{type:'bar', data:[],
              itemStyle:{color: p => p.value > 0 ? '#4f8cff' : '#ff9b3a'}}]
  });

  CHARTS.cpu = echarts.init($('chartCPU'));
  CHARTS.cpu.setOption({
    title: {text: 'CPU 占用 (%) - 服务端 vs 客户端', textStyle:{color:'#e6ecf7', fontSize:13}},
    grid: {top:40, left:50, right:20, bottom:30},
    xAxis: {type:'category', data:[], axisLabel:{color:'#97a4c0', fontSize:10, rotate:45}},
    yAxis: {type:'value', axisLabel:{color:'#97a4c0'}, splitLine:{lineStyle:{color:'#2b3a5e'}}, max:100},
    legend: {data:['服务端', '客户端'], textStyle:{color:'#97a4c0'}, top:25},
    tooltip: {trigger:'axis'},
    series: [
      {name:'服务端', type:'line', smooth:true, data:[], lineStyle:{color:'#ff9b3a'}},
      {name:'客户端', type:'line', smooth:true, data:[], lineStyle:{color:'#4f8cff'}},
    ]
  });

  CHARTS.cmp = echarts.init($('chartCompare'));
  CHARTS.cmp.setOption({
    title: {text: '硬件 vs 软件 后端对比 (吞吐 Mbps)', textStyle:{color:'#e6ecf7', fontSize:13}},
    grid: {top:50, left:50, right:20, bottom:30},
    xAxis: {type:'category', data:['HW (AF_ALG)', 'SOFT (gmssl)'],
            axisLabel:{color:'#97a4c0'}},
    yAxis: {type:'value', axisLabel:{color:'#97a4c0'}, splitLine:{lineStyle:{color:'#2b3a5e'}}},
    tooltip: {trigger:'axis'},
    legend: {data:['平均吞吐'], textStyle:{color:'#97a4c0'}, top:25},
    series: [{name:'平均吞吐', type:'bar', data:[
      {value:0, itemStyle:{color:'#00e2c0'}},
      {value:0, itemStyle:{color:'#4f8cff'}},
    ]}]
  });

  window.addEventListener('resize', () => {
    Object.values(CHARTS).forEach(c => c.resize());
  });
}

const histThr = [], histLat = [], histCpuS = [], histCpuC = [], histLabels = [];
const sumByBackend = {hw: {n:0, thr:0}, soft: {n:0, thr:0}};

function pushPerf(rec) {
  // rec 字段来自 PC 端 perf_log
  const label = (rec.timestamp || rec.ts || '').slice(11);
  histLabels.push(label); if (histLabels.length > 30) histLabels.shift();
  histThr.push(rec.throughput_mbps); if (histThr.length > 30) histThr.shift();
  histLat.push(rec.decrypt_ms || 0); if (histLat.length > 30) histLat.shift();
  histCpuC.push(rec.pc_cpu_percent || 0); if (histCpuC.length > 30) histCpuC.shift();
  // 服务端 CPU 透传可在 record 中扩展, 这里同步一下 ack 返回里包含的字段
  histCpuS.push(rec.server_cpu || 0); if (histCpuS.length > 30) histCpuS.shift();

  CHARTS.thr.setOption({xAxis:{data:histLabels}, series:[{data:histThr}]});
  CHARTS.lat.setOption({xAxis:{data:histLabels}, series:[{data:histLat}]});
  CHARTS.cpu.setOption({xAxis:{data:histLabels}, series:[{data:histCpuS}, {data:histCpuC}]});

  // 累计平均对比
  const b = rec.backend || rec.scenario;
  if (sumByBackend[b]) {
    sumByBackend[b].n += 1;
    sumByBackend[b].thr += rec.throughput_mbps;
  }
  const avgHw = sumByBackend.hw.n   ? sumByBackend.hw.thr  / sumByBackend.hw.n   : 0;
  const avgSf = sumByBackend.soft.n ? sumByBackend.soft.thr/ sumByBackend.soft.n : 0;
  CHARTS.cmp.setOption({series:[{data:[
    {value: avgHw.toFixed(2), itemStyle:{color:'#00e2c0'}},
    {value: avgSf.toFixed(2), itemStyle:{color:'#4f8cff'}},
  ]}]});
}

// ============= WebSocket =============
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  WS = new WebSocket(`${proto}//${location.host}/ws`);
  WS.onmessage = (m) => {
    let ev;
    try { ev = JSON.parse(m.data); } catch(e) { return; }
    handleEvent(ev);
  };
  WS.onclose = () => {
    logLine('WebSocket 断开, 5 秒后重连...', 'log-warn');
    setTimeout(connectWS, 5000);
  };
}

function handleEvent(ev) {
  switch(ev.type) {
    case 'snapshot':
      applyStatus(ev.status); break;
    case 'log':
      logLine(ev.msg, 'log-info'); break;
    case 'handshake':
      if (ev.stage === 'done') {
        logLine(ev.msg, 'log-ok');
        $('hsState').textContent = '已协商';
        $('keyId').textContent = ev.key_id;
      } else {
        logLine(ev.msg, 'log-stage');
      }
      break;
    case 'transfer':
      if (ev.stage === 'progress') {
        const pct = ev.percent;
        $('progBar').style.width = pct + '%';
        $('progText').textContent = pct + '%';
        if (ev.ciphertext_preview) {
          appendHex(ev.ciphertext_preview);
        }
      } else if (ev.stage === 'begin') {
        logLine(ev.msg, 'log-stage');
        $('progBar').style.width = '0%';
        $('progText').textContent = '0%';
      } else if (ev.stage === 'done') {
        logLine(ev.msg, 'log-ok');
        $('progBar').style.width = '100%';
        $('progText').textContent = '100%';
        if (ev.record) pushPerf(ev.record);
      }
      break;
    case 'perf':
      if (ev.record) pushPerf(ev.record);
      break;
  }
}

function appendHex(hex) {
  const box = $('hexStream');
  // 每 32 字符一行, 加点空格美化
  const formatted = hex.match(/.{1,2}/g).join(' ');
  box.textContent = (box.textContent + '\n' + formatted).split('\n').slice(-30).join('\n');
  box.scrollTop = box.scrollHeight;
}

// ============= 状态查询 =============
async function refreshStatus() {
  try {
    const s = await api('/api/status');
    applyStatus(s);
  } catch(e) {}
}

function applyStatus(s) {
  $('selfId').textContent = s.self_id || '-';
  $('peerId').textContent = (s.peer_id || '-') + (s.peer_loaded ? ' (已配置)' : ' (未配置)');
  $('hsState').textContent = s.handshaked ? '已协商' : '未协商';
  $('keyId').textContent = s.key_id || '-';
  $('rekeyCount').textContent = s.rekey_count || 0;
  $('hwBackend').textContent = s.backends ?
    (s.backends.hw ? 'AF_ALG ✓ 可用' : 'PC 端为软件') : '-';
  const badge = $('connBadge');
  badge.textContent = s.connected ? '已连接' : '未连接';
  badge.classList.toggle('ok', !!s.connected);
}

// ============= 控制按钮 =============
$('btnConnect').addEventListener('click', async () => {
  try {
    await api('/api/connect', {method:'POST', body:{
      host: $('host').value, port: parseInt($('port').value)
    }});
    logLine('TCP 连接已建立', 'log-ok');
    refreshStatus();
  } catch(e) { logLine('连接失败: ' + e.message, 'log-err'); }
});

$('btnDisconnect').addEventListener('click', async () => {
  try { await api('/api/disconnect', {method:'POST'});
    logLine('已断开', 'log-info'); refreshStatus();
  } catch(e) { logLine(e.message, 'log-err'); }
});

$('btnHandshake').addEventListener('click', async () => {
  try { await api('/api/handshake', {method:'POST'}); }
  catch(e) { logLine('握手失败: ' + e.message, 'log-err'); }
});

$('btnRekey').addEventListener('click', async () => {
  // 重新协商 = 再发一次握手
  try {
    await api('/api/handshake', {method:'POST'});
    logLine('已周期换钥', 'log-ok');
  } catch(e) { logLine(e.message, 'log-err'); }
});

$('btnShowPub').addEventListener('click', async () => {
  try {
    const obj = await api('/api/identity/pubkey');
    showModal('本机 SM2 公钥', JSON.stringify(obj, null, 2) +
      '\n\n请将以上 JSON 复制到香橙派的 orangepi_server/data/peer_pubkey.json',
      null, false);
  } catch(e) { logLine(e.message, 'log-err'); }
});

$('btnImportPeer').addEventListener('click', () => {
  showModal('导入服务端公钥',
    '请粘贴服务端 (香橙派) 的公钥 JSON, 格式如:\n{"id":"server@pi","P":"04...."}',
    async (text) => {
      try {
        const obj = JSON.parse(text);
        await api('/api/identity/peer', {method:'POST', body:obj});
        logLine('已导入服务端公钥: ' + obj.id, 'log-ok');
        refreshStatus();
      } catch(e) { logLine('导入失败: ' + e.message, 'log-err'); }
    }, true);
});

$('fileInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append('file', file);
  try {
    const r = await api('/api/upload', {method:'POST', body: fd});
    LAST_UPLOAD = r.path;
    logLine(`已暂存 ${file.name} (${r.size} 字节), 点击 "SM4 加密发送" 开始传输`, 'log-info');
  } catch(err) { logLine('上传失败: ' + err.message, 'log-err'); }
});

$('btnSend').addEventListener('click', async () => {
  if (!LAST_UPLOAD) { logLine('请先选择文件', 'log-warn'); return; }
  const backend = document.querySelector('input[name=backend]:checked').value;
  try {
    await api('/api/send', {method:'POST', body:{
      filepath: LAST_UPLOAD, scenario: backend
    }});
  } catch(e) { logLine('发送失败: ' + e.message, 'log-err'); }
});

$('btnExportCSV').addEventListener('click', async () => {
  try {
    const blob = await api('/api/perf/csv');
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'performance_log.csv';
    a.click();
    URL.revokeObjectURL(url);
    logLine('已导出 performance_log.csv', 'log-ok');
  } catch(e) { logLine(e.message, 'log-err'); }
});

$('btnClearLog').addEventListener('click', () => {
  $('logBox').innerHTML = '';
  $('hexStream').textContent = '';
});

// ============= 启动 =============
checkLoginStatus();
