/**
 * 网络拓扑管理系统 - Node.js 后端 API
 * 支持 SSH 登录交换机、采集 LLDP/SNMP 数据、生成拓扑图
 */

'use strict';

const express = require('express');
const cors = require('cors');
const { Client } = require('ssh2');
const snmp = require('net-snmp');
const ping = require('ping');
const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');

// ── 全局错误处理，防止进程崩溃 ──
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT]', err.message, err.stack ? err.stack.split('\n').slice(0, 3).join(' ') : '');
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('[UNHANDLED]', String(reason));
});

const app = express();
app.use(cors());
app.use(express.json());

// ── 静态文件：前端页面在 app/ 目录 ──
app.use(express.static(path.join(__dirname, '../')));

// ============================================================
// 全局状态
// ============================================================
let scanStatus = { running: false, progress: 0, message: '' };
let lastTopology = { nodes: [], links: [] };
let lastScanCommunity = 'public'; // 记录最近一次扫描使用的 SNMP community

// 拓扑缓存文件路径（与 server.js 同目录的 data/ 下）
const CACHE_DIR = path.join(__dirname, 'data');
const CACHE_FILE = path.join(CACHE_DIR, 'topology-cache.json');

// 启动时自动加载缓存
try {
  if (fs.existsSync(CACHE_FILE)) {
    const cached = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    if (cached && cached.nodes && cached.nodes.length > 0) {
      lastTopology = cached;
      console.log('[CACHE] 已加载拓扑缓存：' + cached.nodes.length + ' 台设备，' + (cached.links || []).length + ' 条链路');
      scanStatus.message = '已加载上次扫描结果（' + cached.nodes.length + ' 台设备），点击"重新扫描"更新';
    }
  }
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
} catch (e) {
  console.log('[CACHE] 加载缓存失败：' + e.message);
  if (!fs.existsSync(CACHE_DIR)) {
    try { fs.mkdirSync(CACHE_DIR, { recursive: true }); } catch (_) {}
  }
}

// 保存拓扑到缓存文件
function saveCache(topology) {
  try {
    if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
    const data = {
      nodes: topology.nodes,
      links: topology.links,
      savedAt: new Date().toISOString()
    };
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2), 'utf8');
    console.log('[CACHE] 拓扑已缓存：' + data.nodes.length + ' 台设备');
  } catch (e) {
    console.log('[CACHE] 保存缓存失败：' + e.message);
  }
}

// ============================================================
// SSH 工具函数
// ============================================================

// SSH 算法配置（最大兼容性，涵盖新老设备）
const SSH_ALGORITHMS = {
  kex: [
    // 现代算法（不含 GEX，避免 "DH GEX group out of range"）
    'ecdh-sha2-nistp256','ecdh-sha2-nistp384','ecdh-sha2-nistp521',
    'diffie-hellman-group14-sha256','diffie-hellman-group16-sha512',
    'diffie-hellman-group18-sha512',
    // 老设备常用（锐捷/华为老固件）
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group1-sha1'   // 老设备兜底
  ],
  cipher: [
    'aes128-ctr','aes192-ctr','aes256-ctr',
    'aes128-gcm@openssh.com','aes256-gcm@openssh.com',
    'aes128-cbc','aes192-cbc','aes256-cbc',
    '3des-cbc'                     // 老设备兜底
  ],
  serverHostKey: [
    'ssh-rsa','rsa-sha2-256','rsa-sha2-512',
    'ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521',
    'ssh-ed25519',
    'ssh-dss'                      // 老设备
  ],
  hmac: [
    'hmac-sha2-256','hmac-sha2-512',
    'hmac-sha1','hmac-sha1-96',
    'hmac-md5','hmac-md5-96'       // 老设备兜底
  ]
};

// exec 模式（适合 Cisco/H3C 等标准 SSH 设备）
function sshExec(host, port, username, password, command, timeout) {
  timeout = timeout || 10000;
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let output = '';
    let errOutput = '';
    const timer = setTimeout(() => { try{ conn.end(); }catch(_){} reject(new Error('SSH 连接超时')); }, timeout);

    // ── keyboard-interactive 必须在 connect() 之前注册 ──
    conn.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
      finish([password]);
    });

    conn.on('ready', () => {
      conn.exec(command, { pty: false }, (err, stream) => {
        if (err) { clearTimeout(timer); conn.end(); reject(err); return; }
        stream.on('data', (d) => { output += d.toString(); });
        stream.stderr.on('data', (d) => { errOutput += d.toString(); });
        stream.on('close', () => { clearTimeout(timer); conn.end(); resolve({ output, error: errOutput }); });
      });
    });

    conn.on('error', (err) => { clearTimeout(timer); reject(err); });
    conn.connect({
      host, port: port || 22, username, password,
      readyTimeout: timeout,
      algorithms: SSH_ALGORITHMS,
      tryKeyboard: true
    });
  });
}

// shell 模式（适合华为 VRP / 锐捷等只支持 shell 通道的设备）
function sshShell(host, port, username, password, commands, timeout) {
  timeout = timeout || 15000;
  if (!Array.isArray(commands)) commands = [commands];
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let output = '';
    const timer = setTimeout(() => {
      try{ conn.end(); }catch(_){}
      if (output.length > 50) resolve({ output, error: '' });
      else reject(new Error('Shell 会话超时'));
    }, timeout);

    // ── keyboard-interactive 必须在 connect() 之前注册 ──
    conn.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
      finish([password]);
    });

    conn.on('ready', () => {
      conn.shell({ term: 'vt100', cols: 200, rows: 50 }, (err, stream) => {
        if (err) { clearTimeout(timer); conn.end(); reject(err); return; }

        stream.on('data', (d) => { output += d.toString(); });
        stream.stderr.on('data', (d) => { output += d.toString(); });

        // 等设备提示符出现后依次发送命令
        let cmdIdx = 0;
        let promptWait = null;

        function sendNext() {
          if (cmdIdx < commands.length) {
            const cmd = commands[cmdIdx++];
            stream.write(cmd + '\n');
            // 等待每条命令输出稳定（300ms 内无新数据则认为输出完毕）
            if (promptWait) clearTimeout(promptWait);
            promptWait = setTimeout(sendNext, 1200);
          } else {
            // 所有命令已发送，再等 2s 收全输出
            if (promptWait) clearTimeout(promptWait);
            setTimeout(() => {
              clearTimeout(timer);
              try{ stream.end(); conn.end(); }catch(_){}
              resolve({ output, error: '' });
            }, 2000);
          }
        }

        // 等待登录提示（最多 4s）
        setTimeout(sendNext, 1500);

        stream.on('close', () => {
          clearTimeout(timer);
          if (promptWait) clearTimeout(promptWait);
          resolve({ output, error: '' });
        });
      });
    });

    conn.on('error', (err) => { clearTimeout(timer); reject(err); });
    conn.connect({
      host, port: port || 22, username, password,
      readyTimeout: timeout,
      algorithms: SSH_ALGORITHMS,
      tryKeyboard: true
    });
  });
}

// 智能模式：先尝试 exec，若失败自动降级为 shell
async function sshRun(host, port, username, password, command, timeout) {
  try {
    return await sshExec(host, port, username, password, command, timeout || 10000);
  } catch (execErr) {
    // exec 失败（如 ECONNRESET / Channel open failure），降级到 shell
    try {
      return await sshShell(host, port, username, password,
        ['screen-length 0 temporary', command],
        (timeout || 10000) + 5000);
    } catch (shellErr) {
      throw new Error(`exec: ${execErr.message} | shell: ${shellErr.message}`);
    }
  }
}

// ============================================================
// 设备指纹识别 & 命令库
// ============================================================

// 从 SSH banner、version 输出、SNMP sysDescr 中识别厂商
// 注意顺序很重要：锐捷要在 H3C/Comware 之前，因为某些锐捷输出也含 Comware 字样
function detectVendor(banner, snmpDescr) {
  const combined = ((banner || '') + ' ' + (snmpDescr || '')).toLowerCase();
  if (!combined.trim()) return 'unknown';

  // 锐捷（Ruijie/RGOS）— 优先检测，避免被 H3C 规则误判
  if (combined.includes('ruijie') || combined.includes('rgos') ||
      combined.includes('rg-') || combined.includes('s5750') ||
      combined.includes('s6000') || combined.includes('s8600') ||
      combined.includes('s8607') || combined.includes('nbr') ||
      combined.includes('reyee')) return 'ruijie';

  // 华为（Huawei/VRP）
  if (combined.includes('huawei') || combined.includes('vrp') ||
      combined.includes('quidway') || combined.includes('cloudengine') ||
      combined.includes('ce6800') || combined.includes('ce12800') ||
      combined.includes('s5700') || combined.includes('s6700') ||
      combined.includes('ar') && combined.includes('vrp')) return 'huawei';

  // Cisco
  if (combined.includes('cisco') || combined.includes('ios-xe') ||
      combined.includes('ios xe') || combined.includes('nexus') ||
      combined.includes('catalyst') || combined.includes('nx-os')) return 'cisco';

  // H3C（Comware）
  if (combined.includes('h3c') || combined.includes('comware') ||
      combined.includes('hp flexfabric') || combined.includes('hpe')) return 'h3c';

  // 瞻博
  if (combined.includes('juniper') || combined.includes('junos')) return 'juniper';

  // Arista
  if (combined.includes('arista') || combined.includes('eos')) return 'arista';

  // 中兴（ZTE/ZXR10）
  if (combined.includes('zte') || combined.includes('zxr')) return 'zte';

  // 海康威视（Hikvision）— 监控交换机/IPC/NVR
  if (combined.includes('hikvision') || combined.includes('hik-') ||
      combined.includes('ds-3e') || combined.includes('ds-2c') ||
      combined.includes('ds-2d') || combined.includes('ds-7')) return 'hikvision';

  // 大华（Dahua）
  if (combined.includes('dahua') || combined.includes('dhi-') ||
      combined.includes('dh-') || combined.includes('ipc-')) return 'dahua';

  // TP-Link（企业级交换机）
  if (combined.includes('tp-link') || combined.includes('tplink') ||
      combined.includes('tl-sg') || combined.includes('tl-sl')) return 'tplink';

  // Ruijie Reyee（锐捷睿易）— 智能网络
  if (combined.includes('reyee') || combined.includes('eap')) return 'ruijie';

  // Dell（PowerSwitch）
  if (combined.includes('dell') || combined.includes('powerconnect') ||
      combined.includes('os6') || combined.includes('os10')) return 'dell';

  // 再宽泛匹配 IOS（防止 show version 里只有 IOS）
  if (combined.includes(' ios ') && !combined.includes('bios')) return 'cisco';

  return 'unknown';
}

const CMDS = {
  huawei: {
    version: 'display version',
    lldp:    'display lldp neighbor',
    lldpDetail: 'display lldp neighbor detail',
    hostname: 'display current-configuration | include sysname',
    iface:   'display interface brief',
    noPager: 'screen-length 0 temporary'
  },
  cisco: {
    version: 'show version',
    lldp:    'show lldp neighbors',
    lldpDetail: 'show lldp neighbors detail',
    hostname: 'show running-config | include hostname',
    iface:   'show interfaces status',
    noPager: 'terminal length 0'
  },
  h3c: {
    version: 'display version',
    lldp:    'display lldp neighbor-information list',
    lldpDetail: 'display lldp neighbor-information verbose',
    hostname: 'display current-configuration | include sysname',
    iface:   'display interface brief',
    noPager: 'screen-length disable'
  },
  ruijie: {
    version: 'show version',
    lldp:    'show lldp neighbors',
    lldpDetail: 'show lldp neighbors detail',
    hostname: 'show running-config | include hostname',
    iface:   'show interfaces status',
    noPager: 'terminal length 0'
  },
  zte: {
    version: 'show version',
    lldp:    'show lldp neighbors',
    lldpDetail: 'show lldp neighbors detail',
    hostname: 'show running-config | include hostname',
    iface:   'show interfaces',
    noPager: 'terminal length 0'
  },
  unknown: {
    version: 'show version',
    lldp:    'show lldp neighbors',
    lldpDetail: 'show lldp neighbors',
    hostname: 'show running-config | include hostname',
    iface:   'show interfaces',
    noPager: 'terminal length 0'
  },
  hikvision: {
    // 海康威视交换机 CLI 兼容 Cisco 风格
    version: 'show version',
    lldp:    'show lldp neighbors',
    lldpDetail: 'show lldp neighbors detail',
    hostname: 'show running-config | include hostname',
    iface:   'show interfaces status',
    noPager: 'terminal length 0'
  },
  dahua: {
    // 大华交换机 CLI 兼容 Cisco 风格
    version: 'show version',
    lldp:    'show lldp neighbors',
    lldpDetail: 'show lldp neighbors detail',
    hostname: 'show running-config | include hostname',
    iface:   'show interfaces status',
    noPager: 'terminal length 0'
  },
  tplink: {
    // TP-Link JetStream CLI
    version: 'show version',
    lldp:    'show lldp neighbors',
    lldpDetail: 'show lldp neighbors detail',
    hostname: 'show running-config | include hostname',
    iface:   'show interfaces status',
    noPager: 'terminal length 0'
  },
  dell: {
    // Dell OS6/OS10 CLI
    version: 'show version',
    lldp:    'show lldp neighbors',
    lldpDetail: 'show lldp neighbors detail',
    hostname: 'show running-config | include hostname',
    iface:   'show interfaces status',
    noPager: 'terminal length 0'
  }
};

// ============================================================
// 版本信息解析
// ============================================================
function parseVersion(output, vendor) {
  let model = 'Unknown', version = 'Unknown';
  if (!output) return { model, version };

  if (vendor === 'huawei') {
    // 华为 CloudEngine: CE6870 CE12800 etc.
    const mCE = output.match(/HUAWEI\s+([\w-]+)\s+uptime|Huawei\s+Versatile\s+Routing\s+Platform.*?Version\s+([\d.]+)|Product\s+Name\s*:\s*([\w -]+)/i);
    if (mCE) model = (mCE[1] || mCE[3] || 'Huawei').trim();
    // 型号：S系列/CE系列
    if (model === 'Unknown') {
      const m2 = output.match(/\b(CE\d+[A-Z0-9-]*|S\d+[A-Z0-9-]*|AR\d+[A-Z0-9-]*)\b/i);
      if (m2) model = m2[1];
    }
    const v = output.match(/VRP.*?V([\d.R]+)/i) || output.match(/Version\s+([\d.R]+)/i);
    if (v) version = 'VRP ' + v[1];

  } else if (vendor === 'cisco') {
    const m = output.match(/Cisco\s+([\w-]+)\s+Software|Model\s+[Nn]umber\s*:\s*(\S+)|cisco\s+(WS-[\w-]+|ASR[\w-]*|ISR[\w-]*|C[\d]+-[\w-]+)/i);
    if (m) model = (m[1] || m[2] || m[3] || 'Cisco').trim();
    const v = output.match(/Version\s+([\d.()A-Za-z]+)/i);
    if (v) version = 'IOS ' + v[1];

  } else if (vendor === 'h3c') {
    const m = output.match(/H3C\s+([\w-]+)|HPE?\s+([\w-]+)\s+Switch|Product\s+Name\s*:\s*([\w -]+)/i);
    if (m) model = (m[1] || m[2] || m[3] || 'H3C').trim();
    const v = output.match(/Software\s+Version\s+([\d.a-zA-Z]+)/i);
    if (v) version = 'Comware ' + v[1];

  } else if (vendor === 'ruijie') {
    // 锐捷：从 show version 和 SNMP 解析
    // SNMP sysDescr: "Ruijie 10G Routing Switch(S5750-48GT/4SFP-S) By Ruijie Networks"
    // show version: "Ruijie Networks RG-S5750-48GT/4SFP-S Chassis version: 1.0..."
    const m = output.match(/\(([^)]+)\)\s+By\s+Ruijie/i) ||  // SNMP 格式
              output.match(/RG-([\w/-]+)\s/i) ||              // show version 格式
              output.match(/Ruijie\s+([\w-]+)/i);
    if (m) model = (m[1] || 'Ruijie').trim();
    const v = output.match(/RGOS.*?V([\d.]+)/i) || output.match(/Version\s*[:\(]?\s*([\d.]+)/i);
    if (v) version = 'RGOS ' + v[1];

  } else if (vendor === 'zte') {
    const m = output.match(/ZXR?\s+([\w-]+)/i);
    if (m) model = m[1];
    const v = output.match(/Version\s+([\d.]+)/i);
    if (v) version = 'ZTE ' + v[1];

  } else if (vendor === 'hikvision') {
    // 海康威视 sysDescr 示例:
    // "Hikvision DS-3E0326P-EI Ethernet Switch, V5.4.102 Build 20230308"
    // "Hikvision DS-3E0318P-E Hardware Version:V2.0 Software Version:V5.4.106"
    const m = output.match(/(DS-[23][EC][\w-]+)/i);
    if (m) model = m[1];
    // 尝试多个版本格式
    const v = output.match(/Software\s*Version\s*:\s*(V?[\d.]+)/i) ||
              output.match(/Version\s*:\s*(V?[\d.]+)/i) ||
              output.match(/,\s*V([\d.]+)/i) ||
              output.match(/V([\d.]+)\s*Build/i);
    if (v) version = 'V' + v[1].replace(/^V/i, '');

  } else if (vendor === 'dahua') {
    // 大华 sysDescr 示例:
    // "Dahua DH-SW3018P-ET Hardware Version:1.0 Software Version:V2.1.0"
    const m = output.match(/(DH-SW[\w-]+)/i) || output.match(/Dahua\s+([\w-]+)/i);
    if (m) model = m[1];
    const v = output.match(/Software\s*Version\s*:\s*(V?[\d.]+)/i) ||
              output.match(/Version\s*:\s*(V?[\d.]+)/i);
    if (v) version = 'V' + v[1].replace(/^V/i, '');

  } else if (vendor === 'tplink') {
    // TP-Link sysDescr 示例:
    // "TP-LINK JetStream S3800-24T, Firmware Version: 2.0.0 Build 20230919"
    // "TP-LINK TL-SG3428, Hardware Version:V3.0 Firmware Version:2.0.0"
    const m = output.match(/(TL-S[GESL][\w-]+)/i) ||
              output.match(/(S\d{4}[\w-]*)/i) ||
              output.match(/TP-?Link\s+([\w-]+)/i);
    if (m) model = m[1];
    const v = output.match(/Firmware\s*Version\s*:\s*([\d.]+)/i) ||
              output.match(/Version\s*:\s*([\d.]+)/i);
    if (v) version = 'FW ' + v[1];

  } else if (vendor === 'dell') {
    // Dell sysDescr 示例:
    // "Dell Networking OS6, Version 6.6.1.3"
    // "Dell EMC Networking OS10, Version 10.5.1.1"
    const m = output.match(/(PowerConnect\s+[\w-]+|N\d{4,}[\w-]*|S\d{4,}[\w-]*)/i) ||
              output.match(/Dell\s+(?:EMC\s+)?Networking\s+([\w]+)/i);
    if (m) model = m[1];
    const v = output.match(/Version\s+([\d.]+)/i);
    if (v) version = 'Dell ' + v[1];

  } else {
    // 通用解析：尝试从任何文本中提取型号和版本
    // 匹配常见格式: "Brand ModelName, Version X.Y.Z"
    const m = output.match(/^([A-Za-z][\w -]+?)\s+Version|^([A-Za-z][\w -]+?),/i);
    if (m) model = (m[1] || m[2] || '').trim();
    if (model === 'Unknown') {
      // 尝试提取大写字母+数字组合的型号
      const m2 = output.match(/\b([A-Z]{2,}[\w-]{3,})\b/);
      if (m2) model = m2[1];
    }
    const v = output.match(/Version\s*[:=]?\s*([\d.]+\w*)/i) ||
              output.match(/V([\d.]+[A-Za-z]*)/i);
    if (v) version = v[1] || v[2] || version;
  }

  return { model, version };
}

function parseHostname(output, vendor) {
  if (!output) return '';
  let hn = '';

  if (vendor === 'huawei' || vendor === 'h3c') {
    // 华为/H3C: sysname HOSTNAME
    const m = output.match(/sysname\s+(\S+)/i);
    if (m) hn = m[1];
    // 也可能从提示符猜: <HOSTNAME> 或 [HOSTNAME]
    if (!hn) {
      const p = output.match(/[<\[]([\w\-\.]+)[>\]]\s*(?:\n|$)/m);
      if (p) hn = p[1];
    }
  } else if (vendor === 'ruijie' || vendor === 'cisco' || vendor === 'zte') {
    // Cisco/Ruijie: hostname HOSTNAME
    const m = output.match(/^hostname\s+(\S+)/im);
    if (m) hn = m[1];
    // 从提示符猜: HOSTNAME# 或 HOSTNAME>
    if (!hn) {
      const p = output.match(/^([\w\-\.]+)[#>]\s*(?:terminal|show|display|\n|$)/m);
      if (p) hn = p[1];
    }
  } else {
    // 通用：先 hostname 命令，再提示符
    const m = output.match(/^hostname\s+(\S+)/im) || output.match(/sysname\s+(\S+)/i);
    if (m) hn = m[1];
  }

  // 过滤掉无效值（单个字符、纯符号、 % 等）
  if (hn && (hn.length <= 1 || /^[%#>\[\]<]+$/.test(hn))) hn = '';

  return hn || '';
}

// ============================================================
// LLDP 邻居解析
// ============================================================
function parseLLDPHuawei(output, selfIp) {
  const neighbors = [];
  // 华为格式：多行块，每块一个邻居
  const blocks = output.split(/\n(?=\S)/);
  for (const block of blocks) {
    const portLine = block.match(/^(\S+\d+)\s+has\s+\d+\s+neighbor|Local Interface\s*:\s*(\S+)/im);
    const sysName = block.match(/System Name\s*:\s*(.+)/i);
    const portId  = block.match(/Port ID\s*:\s*(.+)/i);
    const mgmtIp  = block.match(/Management Address\s*:\s*([\d.]+)/i);
    const portDesc= block.match(/Port Description\s*:\s*(.+)/i);
    const sysDesc = block.match(/System Description\s*:\s*(.+)/i);

    if (sysName || portId) {
      neighbors.push({
        local_port: portLine ? (portLine[1] || portLine[2] || '').trim() : '',
        remote_name: sysName ? sysName[1].trim() : '',
        remote_port: portId  ? portId[1].trim()  : '',
        remote_mgmt: mgmtIp  ? mgmtIp[1].trim()  : '',
        port_desc:   portDesc ? portDesc[1].trim() : '',
        sys_desc:    sysDesc  ? sysDesc[1].trim()  : ''
      });
    }
  }
  return neighbors;
}

function parseLLDPCisco(output, selfIp) {
  const neighbors = [];
  // Cisco 格式：表格，设备ID  本地接口  ...  端口ID
  const lines = output.split('\n');
  let inTable = false;
  for (const line of lines) {
    if (line.match(/^-{5,}/)) { inTable = true; continue; }
    if (!inTable) continue;
    const parts = line.trim().split(/\s{2,}/);
    if (parts.length >= 5) {
      neighbors.push({
        remote_name: parts[0] || '',
        local_port:  parts[1] || '',
        remote_port: parts[4] || '',
        remote_mgmt: '',
        port_desc:   '',
        sys_desc:    ''
      });
    }
  }
  return neighbors;
}

function parseLLDPGeneric(output, vendor, selfIp) {
  if (vendor === 'huawei' || vendor === 'h3c') return parseLLDPHuawei(output, selfIp);
  return parseLLDPCisco(output, selfIp);
}

// ============================================================
// 链路速率判断
// ============================================================

// bps 值转换为可读字符串
// ifSpeed=4294967295 表示"自动协商未获取到实际速率"，此时需结合端口名推断
function _formatBps(bps, portName) {
  if (!bps || bps <= 0) return '';
  const port = (portName || '').toLowerCase();
  // 4294967295 = 0xFFFFFFFF = "auto/unknown"（未协商到具体速率）
  // 常见场景：10GE 光口插入 1GE 光模块后，ifSpeed 可能仍为 4294967295
  if (bps === 4294967295) {
    if (port.includes('tengig') || port.includes('10ge') || port.includes('xg')) return '10Gbps(1G光模块)';
    if (port.includes('gig') || port.includes('ge') || port.includes('gi')) return '1Gbps';
    return '1Gbps+'; // fallback
  }
  const mbps = Math.round(bps / 1000000);
  if (mbps >= 100000) return (mbps / 1000) + 'Gbps';
  if (mbps >= 1000)   return (mbps / 1000) + 'Gbps';
  return mbps + 'Mbps';
}

// guessLinkType 只看端口名，不要用 sys_desc（那是设备型号描述，会误判）
function guessLinkType(portName) {
  const p = (portName || '').toLowerCase();
  // 返回值 key 与前端 LKCOLOR 对应，确保颜色映射生效
  if (p.includes('100ge') || p.includes('hundredgig')) return { type: '100G Ethernet', speed: '100Gbps' };
  if (p.includes('40g') || p.includes('fortygig'))        return { type: '40G Ethernet',  speed: '40Gbps'  };
  if (p.includes('25g'))                                  return { type: '25G Ethernet',  speed: '25Gbps'  };
  // Ten-GigabitEthernet / TenGigabitEthernet / XGigabitEthernet / 10ge / xge
  if (p.includes('ten') || p.includes('10ge') || p.includes('xge') || p.startsWith('xg')) {
    return { type: '10G Ethernet', speed: '10Gbps' };
  }
  if (p.includes('lag') || p.includes('eth-trunk') || p.includes('port-channel') || p.includes('aggreg')) {
    return { type: 'LAG 聚合链路', speed: '聚合链路' };
  }
  // GigabitEthernet / Gi / ge（注意 ge 要放在 xge 后面，避免误匹配 TenGigabitEthernet）
  if (p.includes('gigabit') || p.includes('gige') || /\bgi\b/.test(p) || /\bge\b/.test(p)) {
    return { type: '1G Ethernet', speed: '1Gbps' };
  }
  if (p.includes('fa') || p.includes('fast') || p.includes('100m')) {
    return { type: '百兆以太网', speed: '100Mbps' };
  }
  return { type: '以太网', speed: '1Gbps' };
}

// ============================================================
// SNMP 查询（可选增强）
// ============================================================
function snmpGetSysInfo(host, community, timeout) {
  community = community || 'public';
  timeout = timeout || 3000;
  return new Promise((resolve) => {
    const oids = [
      '1.3.6.1.2.1.1.1.0',  // sysDescr
      '1.3.6.1.2.1.1.5.0',  // sysName
      '1.3.6.1.2.1.1.4.0',  // sysContact
      '1.3.6.1.2.1.1.2.0'   // sysObjectID（企业标识，辅助厂商识别）
    ];
    const session = snmp.createSession(host, community, {
      timeout, retries: 1, version: snmp.Version2c
    });
    session.get(oids, (err, varbinds) => {
      session.close();
      if (err) { resolve(null); return; }
      const result = {};
      // 按索引取值，避免 OID 格式前导点不一致的问题
      const toStr = (vb) => {
        if (!vb || snmp.isVarbindError(vb)) return '';
        if (Buffer.isBuffer(vb.value)) return vb.value.toString('utf8').replace(/[\x00-\x1F\x7F]/g, '').trim();
        return vb.value != null ? String(vb.value).trim() : '';
      };
      result.sysDescr   = toStr(varbinds[0]);
      result.sysName    = toStr(varbinds[1]);
      result.sysContact = toStr(varbinds[2]);
      // sysObjectID: 完整 OID 形如 ".1.3.6.1.4.1.9.1.1"，取企业号部分 "1.3.6.1.4.1.xxxxx"
      const oidRaw = toStr(varbinds[3]);
      result.sysObjectID = oidRaw ? oidRaw.replace(/^\.+/, '').split('.').slice(0, 6).join('.') : '';
      // 至少有一个字段有值才算成功
      if (!result.sysDescr && !result.sysName) { resolve(null); return; }
      resolve(result);
    });
  });
}

// ============================================================
// sysObjectID 企业号 → 厂商名 映射表（RFC+常见厂商）
// ============================================================
const VENDOR_OID_MAP = {
  '1.3.6.1.4.1.9':    'cisco',       // Cisco Systems
  '1.3.6.1.4.1.11':   'hp',           // Hewlett-Packard Enterprise
  '1.3.6.1.4.1.25506': 'h3c',         // H3C / TP-Link (overlaps)
  '1.3.6.1.4.1.2636': 'juniper',      // Juniper Networks
  '1.3.6.1.4.1.119':  'huawei',       // Huawei Technologies
  '1.3.6.1.4.1.4881': 'ruijie',       // Ruijie Networks
  '1.3.6.1.4.1.3902': 'zte',          // ZTE Corporation
  '1.3.6.1.4.1.5346': 'arista',       // Arista Networks
  '1.3.6.1.4.1.39471':'hikvision',    // Hikvision Digital Technology
  '1.3.6.1.4.1.4242': 'dell',         // Dell / Dell EMC
};

function detectVendorByOID(oid) {
  if (!oid) return '';
  for (const [prefix, vendor] of Object.entries(VENDOR_OID_MAP)) {
    if (oid.startsWith(prefix)) return vendor;
  }
  return '';
}

// ============================================================
// SNMP LLDP 邻居发现（LLDP-MIB 标准 OID，不依赖 SSH）
// LLDP-MIB 关键 OID:
//   lldpRemChassisId    1.0.8802.1.1.2.1.4.1.1.5
//   lldpRemPortId       1.0.8802.1.1.2.1.4.1.1.7
//   lldpRemPortDesc     1.0.8802.1.1.2.1.4.1.1.8
//   lldpRemSysName      1.0.8802.1.1.2.1.4.1.1.9
//   lldpRemSysDesc      1.0.8802.1.1.2.1.4.1.1.10
//   lldpRemLocalPortId  1.0.8802.1.1.2.1.4.1.1.3
// OID 索引: 1.0.8802.1.1.2.1.4.1.1.<field>.<ifIndex>.<entryIndex>
// ============================================================
function snmpGetLLDPNeighbors(host, community, timeout) {
  timeout = timeout || 8000;
  return new Promise((resolve) => {
    const neighbors = [];
    const base = '1.0.8802.1.1.2.1.4.1.1';  // lldpRemTable columns base

    // 统一 Walk 这几个字段
    // LLDP-MIB lldpRemTable 字段说明：
    //   .3  lldpRemLocalPortId  = 本端端口在 lldpRemTable 中的索引（即 LLDP localPortNum，对应 ifIndex）
    //   .5  lldpRemChassisId    = 对端底盘ID（MAC/IP）
    //   .6  lldpRemPortIdSubtype= 对端端口ID类型（1=接口别名,3=MAC,5=接口名,7=本地值）
    //   .7  lldpRemPortId       = 对端端口ID（格式由.6决定；5=接口名最准确）
    //   .8  lldpRemPortDesc     = 对端端口描述（接口description，可能是别名如"Uplink"）
    //   .9  lldpRemSysName      = 对端设备名
    //   .10 lldpRemSysDesc      = 对端系统描述
    // 结论：本端端口名只能通过 _localIfIdx 反查 ifDescr (ifTable OID 1.3.6.1.2.1.2.2.1.2)
    const fields = [
      { name: 'chassisId',       oid: base + '.5' },
      { name: 'portIdSubtype',   oid: base + '.6' },
      { name: 'portId',          oid: base + '.7' },
      { name: 'portDesc',        oid: base + '.8' },
      { name: 'sysName',         oid: base + '.9' },
      { name: 'sysDesc',         oid: base + '.10' },
      { name: 'localPortNumRaw', oid: base + '.3' },  // lldpRemLocalPortId（很多设备这里是ifIndex数字）
    ];

    const session = snmp.createSession(host, community, {
      timeout, retries: 1, version: snmp.Version2c,
    });

    // 安全超时兜底（即使 walk 没完成也要返回）
    const safetyTimer = setTimeout(() => {
      try { session.close(); } catch (_) {}
      resolve(neighbors); // 返回空数组（SNMP LLDP 不支持）
    }, timeout + 2000);

    // 用一个对象收集所有字段值（按索引组织）
    const neighborMap = {};

    let completed = 0;
    // lldpRemTable OID 索引结构：
    //   <base>.<column>.<timeMark>.<localPortNum>.<remoteIdx>
    // 例：1.0.8802.1.1.2.1.4.1.1.9.3358129796.21.1
    //   column=9, timeMark=3358129796, localPortNum=21, remoteIdx=1
    // base 长度 = "1.0.8802.1.1.2.1.4.1.1".split('.').length = 11
    const BASE_LEN = (base + '.X').split('.').length; // 11+1=12，column 占一段

    // subtree 回调接收 varbinds 数组
    function processVarbinds(field, varbinds) {
      for (const vb of varbinds) {
        if (!vb || !vb.oid || snmp.isVarbindError(vb)) continue;
        const oidParts = vb.oid.split('.');
        const afterBase = oidParts.slice(BASE_LEN); // [timeMark, localPortNum, remoteIdx]
        if (afterBase.length < 2) continue;
        // 取最后 2 段作为 key（localPortNum.remoteIdx）
        const localPortNum = afterBase[afterBase.length - 2];
        const remoteIdx   = afterBase[afterBase.length - 1];
        const key = `${localPortNum}.${remoteIdx}`;
        if (!neighborMap[key]) {
          neighborMap[key] = { _idx: key, _localIfIdx: localPortNum };
        }
        // Buffer → utf8 字符串，非可打印则转 hex
        let val = '';
        if (Buffer.isBuffer(vb.value)) {
          const s = vb.value.toString('utf8').replace(/[\x00-\x1F\x7F]/g, '');
          val = s.length > 0 ? s : vb.value.toString('hex');
        } else {
          val = vb.value != null ? String(vb.value).trim() : '';
        }
        neighborMap[key][field.name] = val;
      }
    }

    fields.forEach((field) => {
      session.subtree(field.oid, 20,
        (varbinds) => processVarbinds(field, varbinds),
        (err) => {
        completed++;
        if (completed === fields.length) {
          // 收集需要反查 ifDescr 的 ifIndex
          const ifIndexSet = new Set(Object.values(neighborMap).map(n => n._localIfIdx));
          const ifDescrMap = {};
          const ifDescrOids = Array.from(ifIndexSet).map(idx => `1.3.6.1.2.1.2.2.1.2.${idx}`);

          const finalize = () => {
            clearTimeout(safetyTimer);
            try { session.close(); } catch (_) {}
            for (const key of Object.keys(neighborMap)) {
              const n = neighborMap[key];
              let neighborId = n.sysName || n.chassisId || n.portId || '';
              let neighborMac = '';
              if (n.chassisId && /^[0-9a-f]{12}$/i.test(n.chassisId.replace(/[^0-9a-fA-F]/g,''))) {
                neighborMac = formatMac(n.chassisId);
              }

              // ── 本端端口名：必须通过 ifDescr 反查，OID 1.3.6.1.2.1.2.2.1.2.<ifIndex> ──
              // _localIfIdx 是 lldpRemTable OID 索引倒数第二段（即 LLDP localPortNum = ifIndex）
              const localPort = ifDescrMap[n._localIfIdx]       // ifDescr（"GigabitEthernet1/0/24"）
                             || `GigabitEthernet 0/${n._localIfIdx}`;  // 兜底

              // ── 对端端口名：优先 portId（.7），类型5=接口名最准确 ──
              // portIdSubtype=5 表示接口名，portIdSubtype=1/7 可能是别名或描述文字
              // portId 若含 "/" 说明是端口号格式，直接用；否则 fallback 到 portDesc
              const pid = n.portId || '';
              const pSubtype = String(n.portIdSubtype || '');
              let remotePort;
              if (pSubtype === '5' || /\//.test(pid)) {
                // 接口名格式（GigabitEthernet1/0/24）或明确是接口名类型
                remotePort = pid;
              } else if (pid && !/Interface$/i.test(pid) && !/^[0-9a-f:]{11,}$/i.test(pid)) {
                // portId 不是 MAC 也不是带 "Interface" 后缀描述，可用
                remotePort = pid;
              } else {
                // portDesc 去掉末尾 " Interface" 后缀
                remotePort = (n.portDesc || '').replace(/ Interface$/i, '').trim() || pid;
              }

              neighbors.push({
                neighborId,
                localPort,                    // 本端端口名（ifDescr 反查）
                localIfIdx: n._localIfIdx,    // 本端 ifIndex 数字（用于查 ifSpeedMap）
                portId:    pid,               // 对端端口ID（lldpRemPortId）
                portDesc:  remotePort,        // 对端端口最终显示值
                portIdSubtype: pSubtype,
                sysName: n.sysName || '',
                sysDesc: n.sysDesc || '',
                chassisId: n.chassisId || '',
                mac: neighborMac
              });
            }
            resolve(neighbors);
          };

          if (ifDescrOids.length === 0) { finalize(); return; }
          session.get(ifDescrOids, (err2, vbs) => {
            if (!err2 && vbs) {
              for (const vb of vbs) {
                if (snmp.isVarbindError(vb)) continue;
                // OID = 1.3.6.1.2.1.2.2.1.2.<ifIndex>
                const idx = vb.oid.split('.').pop();
                let name = Buffer.isBuffer(vb.value)
                  ? vb.value.toString('utf8').replace(/[\x00-\x1F\x7F]/g,'')
                  : String(vb.value);
                if (name) ifDescrMap[idx] = name.trim();
              }
            }
            finalize();
          });
        }
      });
    });
  });
}

// 格式化 MAC 地址（各种格式转标准 XX:XX:XX:XX:XX:XX）
function formatMac(raw) {
  if (!raw) return '';
  // 去掉非十六进制字符后，每2位分组
  const hex = raw.replace(/[^0-9a-fA-F]/g, '');
  if (hex.length === 12) {
    return hex.match(/.{2}/g).join(':').toUpperCase();
  }
  return raw;
}

// 从 chassisId 字段中提取 IP 地址（LLDP chassisIdSubtype = ip(4)）
function extractIpFromChassisId(chassisId) {
  if (!chassisId) return '';
  // 如果是点分十进制 IP，直接返回
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(chassisId)) return chassisId;
  // 如果是十六进制 IP（如 0xAC 0x10 0x10 0x01 = 172.16.16.1），尝试解析
  const hexParts = chassisId.match(/0x([0-9a-fA-F]{2})/gi);
  if (hexParts && hexParts.length >= 4) {
    const ip = hexParts.slice(0, 4).map(h => parseInt(h, 16)).join('.');
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip;
  }
  return '';
}

// ============================================================
// 单台设备采集
// ============================================================

// 采集所有接口的速率（ifSpeed，单位 bps）
// 注意：ifSpeed=4294967295 表示"自动协商"（未见实际协商速率），此时需参考 ifDescr 推断
function snmpGetIfSpeedMap(host, community, timeout) {
  return new Promise((resolve) => {
    const session = snmp.createSession(host, community || 'public', {
      version: snmp.Version2c, timeout: timeout || 5000, retries: 1
    });
    const speedBase = '1.3.6.1.2.1.2.2.1.5';   // ifSpeed (bps)
    const descrBase = '1.3.6.1.2.1.2.2.1.2';  // ifDescr → 用于建立反向索引
    const speedMap = {};
    const ifDescrMap = {};  // ifIndex → ifDescr string (e.g., "GigabitEthernet 1/48")
    const ifDescrByName = {}; // ifDescr string → ifIndex (反向索引)

    let done = 0;
    const checkDone = () => {
      if (++done === 2) {
        // 建立反向索引：ifDescr → ifIndex
        for (const idx of Object.keys(ifDescrMap)) {
          ifDescrByName[ifDescrMap[idx]] = idx;
        }
        session.close();
        resolve({ speedMap, ifDescrByName });
      }
    };

    // 采集 ifSpeed（单位 bps）
    session.subtree(speedBase, 20, (varbinds) => {
      for (const vb of varbinds) {
        if (!vb || snmp.isVarbindError(vb)) continue;
        const ifIdx = vb.oid.split('.').pop();
        const bps = Number(vb.value);
        if (bps > 0) {
          speedMap[ifIdx] = bps;
        }
      }
    }, checkDone);

    // 采集 ifDescr（用于 ifDescr → ifIndex 反向索引）
    session.subtree(descrBase, 20, (varbinds) => {
      for (const vb of varbinds) {
        if (!vb || snmp.isVarbindError(vb)) continue;
        const ifIdx = vb.oid.split('.').pop();
        const name = vb.value.toString('utf8').replace(/[\x00-\x1F]/g, '').trim();
        if (name) {
          ifDescrMap[ifIdx] = name;
        }
      }
    }, checkDone);
  });
}

async function collectDevice(ip, sshPort, username, password, snmpCommunity) {
  const device = {
    ip, hostname: ip, vendor: 'unknown', model: 'Unknown',
    version: 'Unknown', neighbors: [], snmp: null, error: null,
    sshOk: false, sshWarn: null,  // sshOk：SSH是否成功；sshWarn：SSH失败提示（不影响在线状态）
    ifSpeedMap: {}  // ifIndex -> speed string
  };

  // ── 步骤 0：先用 SNMP 采集基础信息（不需要 SSH，速度快）──
  if (snmpCommunity) {
    try {
      device.snmp = await snmpGetSysInfo(ip, snmpCommunity, 4000);
      if (device.snmp) {
        // SNMP 识别厂商（优先 sysDescr 文本，sysObjectID 兜底）
        let snmpVendor = detectVendor('', device.snmp.sysDescr || '');
        if (snmpVendor === 'unknown' && device.snmp.sysObjectID) {
          snmpVendor = detectVendorByOID(device.snmp.sysObjectID);
        }
        if (snmpVendor !== 'unknown') device.vendor = snmpVendor;
        // SNMP hostname
        if (device.snmp.sysName && device.snmp.sysName.trim()) {
          device.hostname = device.snmp.sysName.trim();
        }
        // SNMP 型号（从 sysDescr 解析）
        if (device.snmp.sysDescr) {
          const parsed = parseVersion(device.snmp.sysDescr, device.vendor);
          if (parsed.model !== 'Unknown') device.model = parsed.model;
          if (parsed.version !== 'Unknown') device.version = parsed.version;
        }
        // 采集接口速率表（返回 { speedMap, ifDescrByName }）
        let _snmpIfSpeedResult = {};
        try { _snmpIfSpeedResult = await snmpGetIfSpeedMap(ip, snmpCommunity, 5000); } catch (_) {}
        device.ifSpeedMap = _snmpIfSpeedResult.speedMap || {};
        device.ifDescrByName = _snmpIfSpeedResult.ifDescrByName || {};  // ifDescr → ifIndex 反向索引
      }
    } catch (_) {}
  }

  // ── 步骤 1：SSH 采集（shell 模式，一次性发送所有命令）──
  // 根据 SNMP 已识别的厂商选择正确命令集
  const knownVendor = device.vendor;
  const cmds = CMDS[knownVendor] || CMDS.unknown;

  // 根据已知厂商决定要发送哪些命令
  const shellCmds = [];
  if (knownVendor === 'huawei') {
    shellCmds.push('screen-length 0 temporary', 'display version', 'display lldp neighbor detail', 'display current-configuration | include sysname');
  } else if (knownVendor === 'h3c') {
    shellCmds.push('screen-length disable', 'display version', 'display lldp neighbor-information verbose', 'display current-configuration | include sysname');
  } else if (knownVendor === 'ruijie') {
    shellCmds.push('terminal length 0', 'show version', 'show lldp neighbors detail', 'show running-config | include hostname');
  } else if (knownVendor === 'cisco') {
    shellCmds.push('terminal length 0', 'show version', 'show lldp neighbors detail', 'show running-config | include hostname');
  } else {
    // 未知厂商：全量尝试
    shellCmds.push(
      'screen-length 0 temporary', 'terminal length 0',
      'display version', 'show version',
      'display lldp neighbor detail', 'show lldp neighbors detail',
      'display current-configuration | include sysname',
      'show running-config | include hostname'
    );
  }

  let shellOut = '';
  let sshOk = false;
  let sshFailedReason = '';

  // SSH 凭证为空时跳过 SSH 采集（仅依赖 SNMP）
  if (!username || !password) {
    sshFailedReason = '未提供 SSH 凭证，跳过 SSH 采集（SNMP 模式）';
  } else {
  try {
    const r = await sshShell(ip, sshPort, username, password, shellCmds, 25000);
    shellOut = r.output || '';
    sshOk = shellOut.length > 20;
  } catch (shellErr) {
    sshFailedReason = shellErr.message;
    // shell 失败，尝试 exec
    try {
      const vCmd = (knownVendor === 'huawei' || knownVendor === 'h3c') ? 'display version' : 'show version';
      const r = await sshExec(ip, sshPort, username, password, vCmd, 10000);
      shellOut = r.output || '';
      sshOk = shellOut.length > 20;
      if (!sshOk) sshFailedReason = r.error || shellErr.message;
    } catch (execErr) {
      sshFailedReason = execErr.message;
      // 两种方式都失败，但仍然继续尝试 SNMP LLDP
    }
  }
  }

  // ── 步骤 2：从 SSH 输出中重新识别厂商（可能比 SNMP 更精确）──
  if (sshOk) {
    let sshVendor = detectVendor(shellOut, device.snmp ? device.snmp.sysDescr : '');
    // SSH 也没识别出，用 sysObjectID 兜底
    if (sshVendor === 'unknown' && device.snmp && device.snmp.sysObjectID) {
      sshVendor = detectVendorByOID(device.snmp.sysObjectID);
    }
    if (sshVendor !== 'unknown') device.vendor = sshVendor;

    // 解析版本/型号（SSH 输出 + SNMP 结合）
    const parsed = parseVersion(shellOut + ' ' + (device.snmp ? device.snmp.sysDescr || '' : ''), device.vendor);
    if (parsed.model !== 'Unknown') device.model = parsed.model;
    if (parsed.version !== 'Unknown') device.version = parsed.version;

    // 解析 hostname（SSH 输出优先）
    const hn = parseHostname(shellOut, device.vendor);
    if (hn && hn.length > 1) device.hostname = hn;
    // 如果 SSH 没解析到，用 SNMP
    else if (device.snmp && device.snmp.sysName) device.hostname = device.snmp.sysName.trim();

    // 解析 LLDP 邻居
    device.neighbors = parseLLDPGeneric(shellOut, device.vendor, ip);

    if (device.neighbors.length > 0) {
      // 端口名归一化：LLDP local_port（如 "GigabitEthernet 0/48"）与 ifDescr
      // （如 "GigabitEthernet 1/48"）编号体系可能不同（如 "0/" vs "1/"）
      // 策略：按 ifType+端口ID 匹配，忽略 slot/unit 前缀
      function _normalizePort(p) {
        if (!p) return '';
        // 提取接口类型 + 端口号，如 "GigabitEthernet 0/48" → "ge|48"
        const m = p.match(/^([a-zA-Z]+(?:gig|ge|ten|ten)?(?:gigabit|ethernet|gige|10g|xg)?)\s*[\d\/]+(\d+)$/i)
                 || p.match(/^([a-zA-Z]+)\s*[\d\/]*(\d+)$/);
        if (m) return m[1].toLowerCase() + '|' + m[2];
        return p.toLowerCase();
      }
      const normPort = _normalizePort(nb.local_port);

      // 在 ifDescrByName 中查找匹配的端口
      let matchedBps = 0;
      for (const descr of Object.keys(device.ifDescrByName || {})) {
        if (_normalizePort(descr) === normPort) {
          const idx = device.ifDescrByName[descr];
          matchedBps = device.ifSpeedMap[idx] || 0;
          break;
        }
      }
      nb.local_speed = matchedBps > 0 ? _formatBps(matchedBps, nb.local_port) : '';
    }

    // 如果 LLDP 解析到 0 个邻居，尝试单独执行 LLDP 命令
    if (device.neighbors.length === 0) {
      const lldpCmd = (CMDS[device.vendor] || CMDS.unknown).lldpDetail;
      try {
        const lr = await sshShell(ip, sshPort, username, password,
          [(CMDS[device.vendor] || CMDS.unknown).noPager || 'terminal length 0', lldpCmd], 15000);
        if (lr.output && lr.output.length > 50) {
          device.neighbors = parseLLDPGeneric(lr.output, device.vendor, ip);
        }
      } catch (_) {}
    }
  }

  // ── 步骤 3：SSH LLDP 为空？尝试 SNMP LLDP（LLDP-MIB）──
  // 不管 SSH 成功与否，都尝试 SNMP LLDP，最后合并
  if (snmpCommunity && (device.neighbors.length === 0 || sshFailedReason)) {
    try {
      const snmpNeighbors = await snmpGetLLDPNeighbors(ip, snmpCommunity, 6000);
      if (snmpNeighbors && snmpNeighbors.length > 0) {
        // 建立 ifDescr 全表反向索引：ifDescr → ifIndex（存全部端口，不过滤）
        const ifDescrToIdx = {};
        for (const idx of Object.keys(device.ifSpeedMap)) {
          const descr = device.ifDescrByName[idx] || '';
          if (descr) ifDescrToIdx[descr] = idx;
        }

        const converted = snmpNeighbors.map(n => {
          // 本端端口名：n.localPort 已是 ifDescr 反查结果（如 "GigabitEthernet1/0/24"）
          const displayPort = n.localPort || String(n.localIfIdx || '');

          // 速度查找：优先 ifIndex 直接查 ifSpeedMap（最准确）
          let bps = 0;
          // 第一层：ifIndex 直接查（LLDP OID 的 index = ifIndex）
          if (n.localIfIdx) bps = device.ifSpeedMap[String(n.localIfIdx)] || 0;
          // 第二层：本端 ifDescr 精确匹配（ifDescr 去空格）
          if (bps === 0 && n.localPort) {
            const lpClean = n.localPort.replace(/ /g, '');
            for (const [descr, idx] of Object.entries(ifDescrToIdx)) {
              if (descr.replace(/ /g, '') === lpClean) {
                bps = device.ifSpeedMap[idx] || 0;
                if (bps > 0) break;
              }
            }
          }
          // 第三层：本端端口号尾部模糊匹配（处理 slot 编号差异）
          if (bps === 0 && n.localPort) {
            const portTail = n.localPort.replace(/^[A-Za-z\-\s]+/, '').replace(/ /g, '');
            if (portTail && /\//.test(portTail)) {
              for (const [descr, idx] of Object.entries(ifDescrToIdx)) {
                const dTail = descr.replace(/^[A-Za-z\-\s]+/, '').replace(/ /g, '');
                if (dTail === portTail) {
                  bps = device.ifSpeedMap[idx] || 0;
                  if (bps > 0) break;
                }
              }
            }
          }
          // 第四层：纯数字 ifIndex 容错
          if (bps === 0) {
            for (const k of Object.keys(device.ifSpeedMap)) {
              if (String(k) === String(n.localIfIdx)) { bps = device.ifSpeedMap[k]; break; }
            }
          }
          // 特殊值：SNMP ifSpeed=4294967295 表示"自动协商/未知"，视为 10Gbps
          if (bps === 0xFFFFFFFF) bps = 10000000000;
          // 端口类型强制覆盖：本端端口名含 Ten-Gigabit/XGigabit 但 ifSpeed ≤ 1G
          // 原因：SNMP auto-negotiate 口可能报 1G，但物理口是 10G
          if (bps > 0 && bps <= 1000000000) {
            const portLower = (n.localPort || '').toLowerCase();
            if (portLower.includes('ten') || portLower.includes('xgig') || portLower.includes('10g')) {
              bps = 10000000000; // 10Gbps
            } else if (portLower.includes('fortygig') || portLower.includes('40g')) {
              bps = 40000000000;
            } else if (portLower.includes('hundredgig') || portLower.includes('100g')) {
              bps = 100000000000;
            }
          }

          const speedStr = bps > 0 ? _formatBps(bps, displayPort) : '';
          // 调试日志
          if (bps === 0) {
            const keys = Object.keys(ifDescrToIdx).slice(0, 3);
            console.log('[snmp-lldp] ' + ip + ' ifIdx=' + (n.localIfIdx||'')
              + ' localPort=' + displayPort + ' ifDescr(sample)=' + keys.join(',') + ' → bps=0');
          } else {
            console.log('[snmp-lldp] ' + ip + ' ifIdx=' + (n.localIfIdx||'')
              + ' localPort=' + displayPort + ' bps=' + bps + ' speed=' + speedStr);
          }

          return {
            local_port:  displayPort,        // 本端端口名（ifDescr，如 "GigabitEthernet1/0/24"）
            local_speed: speedStr,
            remote_name: n.sysName    || n.neighborId || 'Unknown',
            remote_port: n.portDesc   || '',  // 对端端口（已处理好的最佳值）
            remote_mgmt: extractIpFromChassisId(n.chassisId),
            port_desc:   n.portDesc   || '',
            sys_desc:    n.sysDesc    || '',
            via:         'SNMP'
          };
        });
        if (device.neighbors.length === 0) {
          device.neighbors = converted;
        } else {
          // 合并去重（SSH 数据优先）
          const existingIds = new Set(device.neighbors.map(n => n.neighborId + '|' + n.localPort));
          converted.forEach(n => {
            const key = n.neighborId + '|' + n.localPort;
            if (!existingIds.has(key)) device.neighbors.push(n);
          });
        }
      }
    } catch (_snmpLldpErr) {
      // SNMP LLDP 失败无所谓，继续
    }
  }

  // ── 步骤 4：设置最终状态──
  // 如果 vendor 还是 unknown，最后用 sysObjectID 兜底
  if (device.vendor === 'unknown' && device.snmp && device.snmp.sysObjectID) {
    const oidVendor = detectVendorByOID(device.snmp.sysObjectID);
    if (oidVendor) device.vendor = oidVendor;
  }

  // error：真实故障（设备SNMP不通 / LLDP全空）；sshWarn：SSH采集失败的提示（不影响在线状态）
  if (!sshOk) {
    const errShort = sshFailedReason ? sshFailedReason.substring(0, 80) : 'SSH连接失败';
    // 只要 SNMP 能识别到设备，就不算故障；SSH 失败只记 sshWarn
    device.sshWarn = `SSH失败(${errShort})`;
  } else if (device.neighbors.length === 0 && device.snmp) {
    device.error = `LLDP邻居为空（可能设备未开启LLDP）`;
  }

  device.sshOk = sshOk;  // 供统计使用，不影响前端状态
  return device;
}

// ============================================================
// 拓扑构建
// ============================================================
function buildTopology(devices) {
  const nodes = [];
  const links = [];
  const linkSet = new Set();
  const deviceMap = {}; // ip -> device

  devices.forEach(d => { deviceMap[d.ip] = d; });

  // 生成节点
  devices.forEach((d, i) => {
    const angle = (2 * Math.PI * i) / devices.length;
    const radius = Math.min(280, 80 + devices.length * 18);
    nodes.push({
      id: d.ip,
      label: d.hostname || d.ip,
      ip: d.ip,
      device_type: d.vendor,
      model: d.model,
      version: d.version,
      neighborCount: d.neighbors.length,
      x: 500 + radius * Math.cos(angle),
      y: 350 + radius * Math.sin(angle),
      error: d.error || null,
      sshWarn: d.sshWarn || null
    });
  });

  // 生成链路（去重）
  // 关键：LLDP 双向报告，同一条物理链路从两端看到 local_port/remote_port 互换
  // 因此去重 key 必须基于设备 IP 对（忽略端口方向），用 sorted pair 确保唯一性
  devices.forEach(d => {
    d.neighbors.forEach(nb => {
      // 找到对端 IP
      let targetIp = nb.remote_mgmt || '';
      if (!targetIp) {
        // 通过 hostname 匹配
        const matched = devices.find(x =>
          x.hostname && nb.remote_name &&
          x.hostname.toLowerCase().includes(nb.remote_name.toLowerCase().substring(0, 8))
        );
        if (matched) targetIp = matched.ip;
      }

      if (!targetIp || targetIp === d.ip) return;
      if (!deviceMap[targetIp]) return; // 对端不在扫描范围内

      // 双向去重 key：按 IP 排序，消除链路方向影响
      const dip = d.ip, tip = targetIp;
      const devPair = dip < tip ? `${dip}||${tip}` : `${tip}||${dip}`;
      if (linkSet.has(devPair)) return;
      linkSet.add(devPair);

      // guessLinkType 用本端端口名（local_port = ifDescr，如 "GigabitEthernet1/0/24"）判断颜色/速率
      const lt = guessLinkType(nb.local_port);
      // 优先使用 SNMP 采集的真实接口速率
      const realSpeed = nb.local_speed || nb.localSpeed || '';
      links.push({
        source: d.ip,
        target: targetIp,
        source_port: nb.local_port,
        target_port: nb.remote_port,
        link_type: lt.type,
        speed: realSpeed || lt.speed
      });
    });
  });

  // ═══ BFS 拓扑分层（自动推断设备层级）══╗
  // 构建邻接表
  const adj = {};
  nodes.forEach(n => { adj[n.ip] = []; });
  links.forEach(l => {
    if (adj[l.source]) adj[l.source].push(l.target);
    if (adj[l.target]) adj[l.target].push(l.source);
  });

  // 找根节点候选（邻居数最多且 >= 3 的设备）
  let rootIp = null;
  let maxNeighbors = 0;
  nodes.forEach(n => {
    const cnt = adj[n.ip] ? adj[n.ip].length : 0;
    if (cnt >= 3 && cnt > maxNeighbors) {
      maxNeighbors = cnt;
      rootIp = n.ip;
    }
  });
  // 如果找不到合适的根，取邻居数最多的设备
  if (!rootIp) {
    nodes.forEach(n => {
      const cnt = adj[n.ip] ? adj[n.ip].length : 0;
      if (cnt > maxNeighbors) {
        maxNeighbors = cnt;
        rootIp = n.ip;
      }
    });
  }

  // BFS 分层
  const ipToNode = {};
  nodes.forEach(n => { ipToNode[n.ip] = n; });

  const layerMap = {};  // ip -> layer number (0=core)
  if (rootIp) {
    const queue = [{ ip: rootIp, layer: 0 }];
    const visited = new Set([rootIp]);
    while (queue.length > 0) {
      const { ip, layer } = queue.shift();
      layerMap[ip] = layer;
      (adj[ip] || []).forEach(nextIp => {
        if (!visited.has(nextIp)) {
          visited.add(nextIp);
          queue.push({ ip: nextIp, layer: layer + 1 });
        }
      });
    }
  }

  // 处理不在 BFS 树中的孤立节点（通过 links 匹配不到的）
  nodes.forEach(n => {
    if (layerMap[n.ip] === undefined) {
      const cnt = adj[n.ip] ? adj[n.ip].length : 0;
      if (cnt <= 1) {
        layerMap[n.ip] = 3; // edge
      } else if (cnt >= 3) {
        layerMap[n.ip] = 0; // core
      } else {
        layerMap[n.ip] = 2; // access
      }
    }
  });

  // 确定实际层数，映射 layer -> role
  const layerRoles = ['core', 'distribution', 'access', 'edge'];
  let actualMaxLayer = 0;
  nodes.forEach(n => {
    const ly = layerMap[n.ip] !== undefined ? layerMap[n.ip] : 2;
    if (ly > actualMaxLayer) actualMaxLayer = ly;
  });

  // 如果只有 1 层，全部标为 access
  // 如果只有 2 层，用 core + access
  // 3 层及以上，用 core + distribution + access (+ edge)
  const effectiveRoles = actualMaxLayer === 0
    ? ['access']
    : actualMaxLayer === 1
    ? ['core', 'access']
    : ['core', 'distribution', 'access', 'edge'];

  // 写入 role 和 layer
  nodes.forEach(n => {
    const ly = layerMap[n.ip] !== undefined ? layerMap[n.ip] : 2;
    const roleIdx = Math.min(ly, effectiveRoles.length - 1);
    n.role = effectiveRoles[roleIdx];
    n.layer = ly;
  });

  return { nodes, links };
}

// ============================================================
// IP 范围解析
// ============================================================
function parseIpRange(rangeStr) {
  const ips = [];
  const parts = rangeStr.split(/[,\n]/).map(s => s.trim()).filter(Boolean);

  for (const part of parts) {
    // CIDR: 192.168.1.0/24
    if (part.includes('/')) {
      try {
        const [baseIp, prefix] = part.split('/');
        const bits = parseInt(prefix);
        if (bits < 16 || bits > 30) continue; // 安全限制
        const ipParts = baseIp.split('.').map(Number);
        const baseNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
        const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
        const start = (baseNum & mask) >>> 0;
        const end = (start | (~mask >>> 0)) >>> 0;
        for (let i = start + 1; i < end; i++) {
          ips.push([(i >>> 24) & 0xFF, (i >>> 16) & 0xFF, (i >>> 8) & 0xFF, i & 0xFF].join('.'));
        }
      } catch (_) {}
    }
    // 范围: 192.168.1.1-50 或 192.168.1.1-192.168.1.50
    else if (part.includes('-')) {
      const [startStr, endStr] = part.split('-');
      if (endStr.includes('.')) {
        // 完整IP范围
        const s = startStr.split('.').map(Number);
        const e = endStr.split('.').map(Number);
        const sNum = (s[0]<<24)|(s[1]<<16)|(s[2]<<8)|s[3];
        const eNum = (e[0]<<24)|(e[1]<<16)|(e[2]<<8)|e[3];
        for (let i = sNum; i <= eNum && i - sNum <= 254; i++) {
          ips.push([(i>>>24)&0xFF,(i>>>16)&0xFF,(i>>>8)&0xFF,i&0xFF].join('.'));
        }
      } else {
        // 最后一段范围
        const baseParts = startStr.split('.');
        const startOct = parseInt(baseParts[3]);
        const endOct = parseInt(endStr);
        const base = baseParts.slice(0, 3).join('.');
        for (let i = startOct; i <= endOct; i++) {
          ips.push(`${base}.${i}`);
        }
      }
    }
    // 单IP
    else if (/^\d+\.\d+\.\d+\.\d+$/.test(part)) {
      ips.push(part);
    }
  }
  return [...new Set(ips)]; // 去重
}

// ============================================================
// TCP 端口探测（快速判断主机是否可达）
// ============================================================
function tcpProbe(host, port, timeout) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(timeout || 2000);
    sock.on('connect', () => { sock.destroy(); resolve(true); });
    sock.on('error', () => { resolve(false); });
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
    sock.connect(port || 22, host);
  });
}

// ============================================================
// SNMP 快速探测（UDP，只取 sysDescr，用于判断主机是否响应 SNMP）
// ============================================================
// ICMP Ping 探测（用于周期性状态检测，替代 snmpProbe）
// 无需 community、无 UDP 资源问题、并发无上限、支持手动添加的设备
// ============================================================
function pingProbe(host, timeoutSec) {
  return ping.promise.probe(host, {
    timeout: timeoutSec || 2,
    packets: 1,
    extra: ['-n', '1', '-w', String((timeoutSec || 2) * 1000)]
  }).then(function(res) {
    var ok = res.alive === true;
    console.log('[pingProbe] ' + (ok ? 'OK' : 'FAIL') + ': ' + host + ' (' + (res.time || '?') + 'ms)');
    return ok;
  }).catch(function(e) {
    console.log('[pingProbe] ERR: ' + host + ' ' + e.message);
    return false;
  });
}

// ============================================================
function snmpProbe(host, community, timeout) {
  return new Promise((resolve) => {
    const SYS_DESCR = '1.3.6.1.2.1.1.1.0';
    let done = false;
    let session;
    const to = timeout || 2000;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      try { session && session.close(); } catch (_) {}
      console.log('[snmpProbe] TIMEOUT: ' + host);
      resolve(false);
    }, to);
    try {
      session = snmp.createSession(host, community, { timeout: to, retries: 1, version: snmp.Version2c });
      session.get([SYS_DESCR], (err, vbs) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try { session.close(); } catch (_) {}
        const ok = !err && vbs && vbs.length > 0;
        console.log('[snmpProbe] ' + (ok ? 'OK' : 'FAIL') + ': ' + host + (err ? ' err=' + err.message : ''));
        resolve(ok);
      });
    } catch (e) {
      if (!done) { done = true; clearTimeout(timer); console.log('[snmpProbe] EXC: ' + host + ' ' + e.message); resolve(false); }
    }
  });
}

// 延迟辅助函数
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================
// API 路由
// ============================================================

// 健康检查
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: Date.now(), version: '1.0.0' });
});

// 扫描进度
app.get('/api/scan/status', (req, res) => {
  res.json(scanStatus);
});

// 执行扫描
app.post('/api/scan', async (req, res) => {
  if (scanStatus.running) {
    return res.status(409).json({ error: '扫描正在进行中，请稍候' });
  }

  const { ip_range, username, password, ssh_port, snmp_community, concurrency } = req.body;
  if (!ip_range) {
    return res.status(400).json({ error: 'IP 范围为必填项' });
  }
  if (!snmp_community) {
    return res.status(400).json({ error: 'SNMP Community 为必填项' });
  }
  lastScanCommunity = snmp_community; // 保存供状态检测使用

  const ips = parseIpRange(ip_range);
  if (ips.length === 0) {
    return res.status(400).json({ error: 'IP 范围格式错误，无法解析出有效 IP' });
  }
  if (ips.length > 254) {
    return res.status(400).json({ error: `IP 数量过多(${ips.length})，单次最多支持 254 个` });
  }

  scanStatus = { running: true, progress: 0, message: `准备扫描 ${ips.length} 个 IP...`, total: ips.length, done: 0, found: 0 };
  res.json({ status: 'started', total: ips.length });

  // 异步执行扫描
  (async () => {
    const maxConcur = Math.min(parseInt(concurrency) || 10, 20);
    const reachable = [];

    // 第一阶段：SNMP 探测（主要手段） + TCP 22 兜底
    // 只要 SNMP 响应 OR SSH 端口通，就认为在线
    scanStatus.message = `主机探测中... (0/${ips.length})`;
    let probed = 0;

    for (let i = 0; i < ips.length; i += maxConcur) {
      const batch = ips.slice(i, i + maxConcur);
      const results = await Promise.all(batch.map(ip =>
        Promise.all([
          snmpProbe(ip, snmp_community || 'public', 2000),
          tcpProbe(ip, ssh_port || 22, 1500)
        ]).then(([snmpOk, tcpOk]) => snmpOk || tcpOk)
      ));
      results.forEach((ok, j) => {
        if (ok) reachable.push(batch[j]);
        probed++;
      });
      scanStatus.progress = Math.round((probed / ips.length) * 40);
      scanStatus.message = `主机探测中... (${probed}/${ips.length})，发现: ${reachable.length}`;
    }

    if (reachable.length === 0) {
      console.log('[scan] No reachable devices found. All IPs: ' + ips.join(', '));
      scanStatus = { running: false, progress: 100, message: '未发现在线设备', total: ips.length, done: ips.length, found: 0 };
      lastTopology = { nodes: [], links: [] };
      return;
    }
    console.log('[scan] Reachable IPs: ' + reachable.join(', '));

    // 第二阶段：SSH 采集
    const collectedDevices = [];
    let collected = 0;
    scanStatus.message = `采集设备数据... (0/${reachable.length})`;

    for (let i = 0; i < reachable.length; i += maxConcur) {
      const batch = reachable.slice(i, i + maxConcur);
      const results = await Promise.all(batch.map(ip =>
        collectDevice(ip, ssh_port || 22, username, password, snmp_community || '')
      ));
      results.forEach(d => { collectedDevices.push(d); collected++; });
      scanStatus.progress = 40 + Math.round((collected / reachable.length) * 55);
      scanStatus.message = `采集设备数据... (${collected}/${reachable.length})`;
    }

    // 第三阶段：构建拓扑（所有设备都显示，包含错误的用警告状态展示）
    scanStatus.message = '构建拓扑图...';
    lastTopology = buildTopology(collectedDevices);
    // 附加所有设备信息
    lastTopology.allDevices = collectedDevices;
    // 自动保存缓存
    saveCache(lastTopology);

    const successDevices = collectedDevices.filter(d => !d.error);
    const sshSuccessCount = collectedDevices.filter(d => d.sshOk).length;
    const snmpOnlyCount = collectedDevices.filter(d => !d.sshOk && d.snmp && d.snmp.sysName).length;
    scanStatus = {
      running: false, progress: 100,
      message: `扫描完成：在线 ${reachable.length} 台，SSH采集 ${sshSuccessCount} 台，纯SNMP ${snmpOnlyCount} 台，发现链路 ${lastTopology.links.length} 条`,
      total: ips.length, done: ips.length, found: successDevices.length
    };
  })().catch(err => {
    scanStatus = { running: false, progress: 0, message: `扫描异常：${err.message}`, error: true };
  });
});

// 获取最新拓扑
app.get('/api/topology', (req, res) => {
  res.json(lastTopology);
});

// 获取缓存状态
app.get('/api/cache-status', (req, res) => {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const stat = fs.statSync(CACHE_FILE);
      const cached = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
      res.json({
        hasCache: true,
        deviceCount: (cached.nodes || []).length,
        linkCount: (cached.links || []).length,
        savedAt: cached.savedAt || stat.mtime.toISOString(),
        fileSize: stat.size
      });
    } else {
      res.json({ hasCache: false });
    }
  } catch (e) {
    res.json({ hasCache: false });
  }
});

// 清除缓存
app.post('/api/cache-clear', (req, res) => {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      fs.unlinkSync(CACHE_FILE);
    }
    lastTopology = { nodes: [], links: [] };
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// 更新设备 role（手动调整层级后保存）
app.post('/api/role-update', (req, res) => {
  const { ip, role } = req.body;
  if (!ip || !role) {
    return res.status(400).json({ error: 'ip 和 role 为必填项' });
  }
  const validRoles = ['core', 'distribution', 'access', 'edge'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: 'role 必须是 core/distribution/access/edge 之一' });
  }
  if (!lastTopology || !lastTopology.nodes) {
    return res.status(404).json({ error: '暂无拓扑数据，请先扫描' });
  }
  let found = false;
  lastTopology.nodes.forEach(n => {
    if (n.id === ip || n.ip === ip) {
      n.role = role;
      // 同步更新 layer
      const layerMap = { core: 0, distribution: 1, access: 2, edge: 3 };
      n.layer = layerMap[role] !== undefined ? layerMap[role] : 2;
      found = true;
    }
  });
  // 同时更新 allDevices 中的 role
  if (lastTopology.allDevices) {
    lastTopology.allDevices.forEach(d => {
      if (d.ip === ip) {
        d.role = role;
      }
    });
  }
  if (!found) {
    return res.status(404).json({ error: '未找到 IP 对应的设备' });
  }
  saveCache(lastTopology);
  res.json({ ok: true, ip, role });
});

// ============================================================
// 设备在线状态检测 & 上下线历史
// ============================================================

// 状态历史文件
const STATUS_HIST_FILE = path.join(CACHE_DIR, 'status-history.json');
const MAX_STATUS_HISTORY = 500;

let statusHistory = [];
try {
  if (fs.existsSync(STATUS_HIST_FILE)) {
    statusHistory = JSON.parse(fs.readFileSync(STATUS_HIST_FILE, 'utf8')) || [];
    console.log('[STATUS] 已加载状态历史：' + statusHistory.length + ' 条');
  }
} catch (e) { statusHistory = []; }

function saveStatusHistory() {
  try {
    if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
    if (statusHistory.length > MAX_STATUS_HISTORY) {
      statusHistory = statusHistory.slice(statusHistory.length - MAX_STATUS_HISTORY);
    }
    fs.writeFileSync(STATUS_HIST_FILE, JSON.stringify(statusHistory, null, 2), 'utf8');
  } catch (e) {
    console.log('[STATUS] 保存历史失败：' + e.message);
  }
}

let prevDeviceStatus = {};

// 设备在线检测（ICMP Ping，覆盖所有设备含手动添加的）
app.get('/api/status-check', async (req, res) => {
  if (!lastTopology || !lastTopology.nodes || lastTopology.nodes.length === 0) {
    return res.json({ devices: {}, links: {}, changes: [], checkedAt: new Date().toISOString(), error: '暂无拓扑数据' });
  }
  const ips = lastTopology.nodes.map(n => n.ip).filter(Boolean);
  if (ips.length === 0) {
    return res.json({ devices: {}, links: {}, changes: [], checkedAt: new Date().toISOString() });
  }
  console.log('[STATUS] 开始 ICMP 检测 ' + ips.length + ' 台, IPs: ' + ips.slice(0, 5).join(',') + (ips.length > 5 ? '...' : ''));
  // ICMP ping 并发检测（无需分批、无需 sleep、无 UDP 资源问题、无 community 依赖）
  const results = await Promise.all(ips.map(ip =>
    pingProbe(ip, 2).then(ok => {
      console.log('[STATUS] ' + ip + ': ICMP=' + ok + ' -> ' + (ok ? 'ONLINE' : 'OFFLINE'));
      return { ip, online: ok };
    })
  ));
  const deviceStatus = {};
  const changes = [];
  const isFirstCheck = Object.keys(prevDeviceStatus).length === 0;
  results.forEach(r => { deviceStatus[r.ip] = r.online ? 'online' : 'offline'; });
  // 首次检测不对比变化（避免全量误报），直接建立基线
  if (isFirstCheck) {
    console.log('[STATUS] 首次检测，建立状态基线，跳过变化对比');
  }
  ips.forEach(ip => {
    if (isFirstCheck) return; // 首次不产生变化记录
    const prev = prevDeviceStatus[ip] || 'online';
    const curr = deviceStatus[ip];
    if (prev !== curr) {
      const node = lastTopology.nodes.find(n => n.ip === ip);
      const hostname = node ? (node.label || node.hostname || ip) : ip;
      const record = { ip: ip, hostname: hostname, event: curr === 'offline' ? 'down' : 'up', prevStatus: prev, newStatus: curr, time: new Date().toISOString() };
      changes.push(record);
      statusHistory.push(record);
      console.log('[STATUS] ' + (curr === 'offline' ? 'DOWN' : 'UP') + ': ' + hostname + ' (' + ip + ')');
    }
  });
  if (changes.length > 0) saveStatusHistory();
  prevDeviceStatus = deviceStatus;
  const linkStatus = {};
  (lastTopology.links || []).forEach((lk, i) => {
    const srcOnline = deviceStatus[lk.source] === 'online';
    const tgtOnline = deviceStatus[lk.target] === 'online';
    linkStatus[i] = (srcOnline && tgtOnline) ? 'up' : 'down';
  });
  const onlineCount = results.filter(r => r.online).length;
  const offlineCount = results.filter(r => !r.online).length;
  console.log('[STATUS] 检测完成：在线 ' + onlineCount + '，离线 ' + offlineCount + (changes.length > 0 ? '，变化 ' + changes.length + ' 台' : ''));
  res.json({ devices: deviceStatus, links: linkStatus, changes: changes, checkedAt: new Date().toISOString(), summary: { total: ips.length, online: onlineCount, offline: offlineCount } });
});

app.get('/api/status-history', (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const records = statusHistory.slice(-limit).reverse();
  res.json({ total: statusHistory.length, records: records });
});

app.post('/api/status-history/clear', (req, res) => {
  statusHistory = [];
  prevDeviceStatus = {};
  try { if (fs.existsSync(STATUS_HIST_FILE)) fs.unlinkSync(STATUS_HIST_FILE); } catch (e) {}
  res.json({ ok: true });
});

// 演示数据（用于测试）
app.get('/api/topology/demo', (req, res) => {
  res.json({
    nodes: [
      { id: '10.0.0.1', label: 'Core-SW-01', ip: '10.0.0.1', vendor: 'huawei', model: 'CE6870', version: 'VRP V200R002C50', neighborCount: 4, x: 500, y: 200 },
      { id: '10.0.0.2', label: 'Core-SW-02', ip: '10.0.0.2', vendor: 'huawei', model: 'CE6870', version: 'VRP V200R002C50', neighborCount: 4, x: 700, y: 200 },
      { id: '10.0.1.1', label: 'Dist-SW-01', ip: '10.0.1.1', vendor: 'cisco',  model: 'Catalyst 3850', version: 'IOS-XE 16.12', neighborCount: 3, x: 300, y: 380 },
      { id: '10.0.1.2', label: 'Dist-SW-02', ip: '10.0.1.2', vendor: 'cisco',  model: 'Catalyst 3850', version: 'IOS-XE 16.12', neighborCount: 3, x: 500, y: 380 },
      { id: '10.0.1.3', label: 'Dist-SW-03', ip: '10.0.1.3', vendor: 'h3c',    model: 'S6800', version: 'Comware 7.1.064', neighborCount: 3, x: 700, y: 380 },
      { id: '10.0.2.1', label: 'Access-01',  ip: '10.0.2.1', vendor: 'ruijie', model: 'RG-S5750', version: 'RGOS 11.4', neighborCount: 1, x: 200, y: 530 },
      { id: '10.0.2.2', label: 'Access-02',  ip: '10.0.2.2', vendor: 'ruijie', model: 'RG-S5750', version: 'RGOS 11.4', neighborCount: 1, x: 380, y: 530 },
      { id: '10.0.2.3', label: 'Access-03',  ip: '10.0.2.3', vendor: 'h3c',    model: 'S5120', version: 'Comware 5.2', neighborCount: 1, x: 570, y: 530 },
      { id: '10.0.2.4', label: 'Access-04',  ip: '10.0.2.4', vendor: 'huawei', model: 'S5735', version: 'VRP V200R019', neighborCount: 1, x: 750, y: 530 }
    ],
    links: [
      { source: '10.0.0.1', target: '10.0.0.2', source_port: 'XGE0/0/1',   target_port: 'XGE0/0/1',   link_type: '万兆光纤',  speed: '10Gbps' },
      { source: '10.0.0.1', target: '10.0.1.1', source_port: 'XGE0/0/2',   target_port: 'XGE0/0/1',   link_type: '万兆光纤',  speed: '10Gbps' },
      { source: '10.0.0.1', target: '10.0.1.2', source_port: 'XGE0/0/3',   target_port: 'XGE0/0/1',   link_type: '万兆光纤',  speed: '10Gbps' },
      { source: '10.0.0.2', target: '10.0.1.2', source_port: 'XGE0/0/2',   target_port: 'XGE0/0/2',   link_type: 'LAG 聚合',  speed: '聚合链路' },
      { source: '10.0.0.2', target: '10.0.1.3', source_port: 'XGE0/0/3',   target_port: 'XGE0/0/1',   link_type: '万兆光纤',  speed: '10Gbps' },
      { source: '10.0.1.1', target: '10.0.2.1', source_port: 'GE0/0/1',    target_port: 'GE0/0/1',    link_type: '千兆以太网', speed: '1Gbps' },
      { source: '10.0.1.1', target: '10.0.2.2', source_port: 'GE0/0/2',    target_port: 'GE0/0/1',    link_type: '千兆以太网', speed: '1Gbps' },
      { source: '10.0.1.2', target: '10.0.2.3', source_port: 'GE1/0/1',    target_port: 'GE0/0/1',    link_type: '千兆以太网', speed: '1Gbps' },
      { source: '10.0.1.3', target: '10.0.2.4', source_port: 'GE1/0/1',    target_port: 'GE0/0/1',    link_type: '千兆以太网', speed: '1Gbps' }
    ]
  });
});

// 单设备详细信息
app.post('/api/device/info', async (req, res) => {
  const { ip, username, password, ssh_port, snmp_community } = req.body;
  if (!ip || !username || !password) {
    return res.status(400).json({ error: 'ip / username / password 为必填项' });
  }
  try {
    const d = await collectDevice(ip, ssh_port || 22, username, password, snmp_community || '');
    res.json(d);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// 手动添加设备到拓扑（支持批量，不重新布局，保留现有节点坐标）
// POST /api/device/add
// body: { ips: ["1.2.3.4", "1.2.3.5"], community?: "public" }
// ============================================================
app.post('/api/device/add', async (req, res) => {
  const { ips, community } = req.body || {};
  if (!ips || !Array.isArray(ips) || ips.length === 0) {
    return res.status(400).json({ error: 'ips 为必填项，格式为 IP 字符串数组' });
  }

  const useCommunity = (community && community.trim()) || lastScanCommunity || 'public';
  const results = [];

  for (const ip of ips) {
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip.trim())) {
      results.push({ ip: ip.trim(), ok: false, error: 'IP 格式错误' });
      continue;
    }
    const cleanIp = ip.trim();

    // 检查是否已存在
    const existing = lastTopology.nodes.find(n => n.ip === cleanIp);
    if (existing) {
      results.push({ ip: cleanIp, ok: false, error: '设备已在拓扑中 (' + (existing.label || existing.hostname || cleanIp) + ')' });
      continue;
    }

    console.log('[ADD] 探测设备 ' + cleanIp + ' (community=' + useCommunity + ')');

    // 新节点基础结构
    let newNode = {
      id: cleanIp,
      ip: cleanIp,
      label: cleanIp,
      hostname: cleanIp,
      vendor: 'unknown',
      device_type: 'unknown',
      model: 'Unknown',
      version: 'Unknown',
      role: 'access',
      layer: 2,
      neighborCount: 0,
      manualAdded: true
    };

    // SNMP 探测基础信息
    try {
      const sysInfo = await snmpGetSysInfo(cleanIp, useCommunity, 4000);
      if (sysInfo) {
        let vendor = detectVendor('', sysInfo.sysDescr || '');
        if (vendor === 'unknown' && sysInfo.sysObjectID) {
          vendor = detectVendorByOID(sysInfo.sysObjectID);
        }
        if (vendor !== 'unknown') newNode.vendor = vendor;
        newNode.device_type = newNode.vendor;
        if (sysInfo.sysName && sysInfo.sysName.trim()) {
          newNode.hostname = sysInfo.sysName.trim();
          newNode.label = sysInfo.sysName.trim();
        }
        if (sysInfo.sysDescr) {
          const parsed = parseVersion(sysInfo.sysDescr, newNode.vendor);
          if (parsed.model !== 'Unknown') newNode.model = parsed.model;
          if (parsed.version !== 'Unknown') newNode.version = parsed.version;
        }
        console.log('[ADD] SNMP OK: ' + cleanIp + ' -> ' + newNode.label + ' (' + newNode.vendor + ')');
      }
    } catch (e) {
      console.log('[ADD] SNMP 探测失败 ' + cleanIp + ': ' + e.message);
    }

    // LLDP 邻居探测 -> 自动发现与现有节点的连接
    const newLinks = [];
    try {
      const ifResult = await snmpGetIfSpeedMap(cleanIp, useCommunity, 5000).catch(() => ({ speedMap: {}, ifDescrByName: {} }));
      const speedMap = ifResult.speedMap || {};
      const ifDescrByName = ifResult.ifDescrByName || {};
      const neighbors = await snmpGetLLDPNeighbors(cleanIp, useCommunity, 5000);
      if (neighbors && neighbors.length > 0) {
        newNode.neighborCount = neighbors.length;
        console.log('[ADD] LLDP 邻居数: ' + neighbors.length);
        for (const nb of neighbors) {
          const remIp = nb.remote_mgmt;
          if (!remIp) continue;
          const existNode = lastTopology.nodes.find(n => n.ip === remIp);
          if (!existNode) continue;
          // 解析速率
          const localIfIdx = ifDescrByName[nb.local_port];
          const speedBps = localIfIdx ? speedMap[localIfIdx] : undefined;
          let speed = 'Unknown';
          if (speedBps) {
            if (speedBps >= 10e9) speed = '10Gbps';
            else if (speedBps >= 1e9) speed = '1Gbps';
            else if (speedBps >= 100e6) speed = '100Mbps';
            else speed = Math.round(speedBps / 1e6) + 'Mbps';
          }
          // 去重（用排序后的 IP 对）
          const linkKey = [cleanIp, remIp].sort().join('||');
          const alreadyExists = lastTopology.links.find(l => [l.source, l.target].sort().join('||') === linkKey)
            || newLinks.find(l => [l.source, l.target].sort().join('||') === linkKey);
          if (!alreadyExists) {
            newLinks.push({
              source: cleanIp,
              target: remIp,
              source_port: nb.local_port || '',
              target_port: nb.remote_port || '',
              link_type: guessLinkType(nb.local_port),
              speed: speed
            });
            console.log('[ADD] 发现链路: ' + cleanIp + ' <-> ' + remIp + ' ' + speed);
          }
        }
      }
    } catch (e) {
      console.log('[ADD] LLDP 探测失败 ' + cleanIp + ': ' + e.message);
    }

    // 根据邻居数推断 role
    if (newNode.neighborCount >= 4) newNode.role = 'core';
    else if (newNode.neighborCount >= 2) newNode.role = 'distribution';
    else newNode.role = 'access';

    // 追加到拓扑（不修改现有节点坐标）
    lastTopology.nodes.push(newNode);
    lastTopology.links.push(...newLinks);
    saveCache(lastTopology);

    results.push({ ip: cleanIp, ok: true, node: newNode, linksAdded: newLinks.length, links: newLinks });
    console.log('[ADD] 完成: ' + cleanIp + ' (' + newNode.label + ')，新链路: ' + newLinks.length);
  }

  res.json({ results: results, topology: lastTopology });
});

// ============================================================
// 删除单台设备（同时删除相关链路）
// DELETE /api/device/remove
// body: { ip: "1.2.3.4" }
// ============================================================
app.delete('/api/device/remove', (req, res) => {
  const { ip } = req.body || {};
  if (!ip) {
    return res.status(400).json({ error: 'ip 为必填项' });
  }

  const nodeIdx = lastTopology.nodes.findIndex(n => n.ip === ip || n.id === ip || n.label === ip);
  if (nodeIdx === -1) {
    return res.status(404).json({ error: '设备不在拓扑中: ' + ip });
  }

  const node = lastTopology.nodes[nodeIdx];
  const nodeId = node.id || node.label || node.ip;
  const nodeIp = node.ip;
  const linkBefore = (lastTopology.links || []).length;

  // 删除节点
  lastTopology.nodes.splice(nodeIdx, 1);

  // 删除相关链路（source 或 target 匹配）
  lastTopology.links = (lastTopology.links || []).filter(l => {
    return l.source !== nodeIp && l.source !== nodeId
        && l.target !== nodeIp && l.target !== nodeId;
  });

  const linksRemoved = linkBefore - lastTopology.links.length;
  saveCache(lastTopology);
  console.log('[REMOVE] 删除: ' + nodeId + ' (' + nodeIp + ')，清理链路 ' + linksRemoved + ' 条');

  res.json({
    ok: true,
    removed: { ip: nodeIp, label: nodeId },
    linksRemoved: linksRemoved,
    topology: lastTopology
  });
});

// ============================================================
// 手动添加链路
// POST /api/link/add
// body: { source, target, source_port, target_port, link_type, speed }
// source/target 可以是 IP 或 hostname/label
// ============================================================
app.post('/api/link/add', (req, res) => {
  const { source, target, source_port, target_port, link_type, speed } = req.body || {};
  if (!source || !target) {
    return res.status(400).json({ error: 'source 和 target 为必填项' });
  }

  // 查找源节点和目标节点（支持 IP 或 label/hostname 匹配）
  const findNode = (val) => lastTopology.nodes.find(n =>
    n.ip === val || n.id === val || n.label === val || n.hostname === val
  );

  const srcNode = findNode(source);
  const tgtNode = findNode(target);

  if (!srcNode) {
    return res.status(404).json({ error: '找不到源设备: ' + source });
  }
  if (!tgtNode) {
    return res.status(404).json({ error: '找不到目标设备: ' + target });
  }

  const srcIp = srcNode.ip;
  const tgtIp = tgtNode.ip;

  // 检查链路是否已存在（用排序 IP 对去重）
  const key = [srcIp, tgtIp].sort().join('||');
  const exists = (lastTopology.links || []).some(l => {
    const ln = findNode(l.source), lt = findNode(l.target);
    const lSrcIp = ln ? ln.ip : l.source;
    const lTgtIp = lt ? lt.ip : l.target;
    return [lSrcIp, lTgtIp].sort().join('||') === key;
  });
  if (exists) {
    return res.status(409).json({ error: '该链路已存在（两设备间已有连接）' });
  }

  const newLink = {
    source: srcIp,
    target: tgtIp,
    source_port: source_port || '',
    target_port: target_port || '',
    link_type: link_type || '1G Ethernet',
    speed: speed || '1Gbps',
    manual: true
  };

  if (!lastTopology.links) lastTopology.links = [];
  lastTopology.links.push(newLink);
  saveCache(lastTopology);

  console.log('[LINK/ADD] 手动添加链路: ' + srcNode.label + ' <-> ' + tgtNode.label + ' (' + (source_port||'?') + ' / ' + (target_port||'?') + ')');

  res.json({
    ok: true,
    link: newLink,
    srcLabel: srcNode.label || srcNode.id || srcIp,
    tgtLabel: tgtNode.label || tgtNode.id || tgtIp,
    topology: lastTopology
  });
});

// ============================================================
// 手动删除链路
// DELETE /api/link/remove
// body: { source, target }  (IP 或 hostname/label，顺序不限)
// ============================================================
app.delete('/api/link/remove', (req, res) => {
  const { source, target } = req.body || {};
  if (!source || !target) {
    return res.status(400).json({ error: 'source 和 target 为必填项' });
  }

  const findNode = (val) => lastTopology.nodes.find(n =>
    n.ip === val || n.id === val || n.label === val || n.hostname === val
  );

  const srcNode = findNode(source);
  const tgtNode = findNode(target);

  // 支持通过 IP 或节点名匹配
  const srcIp = srcNode ? srcNode.ip : source;
  const tgtIp = tgtNode ? tgtNode.ip : target;
  const key = [srcIp, tgtIp].sort().join('||');

  const before = (lastTopology.links || []).length;
  lastTopology.links = (lastTopology.links || []).filter(l => {
    const ln = findNode(l.source), lt = findNode(l.target);
    const lSrcIp = ln ? ln.ip : l.source;
    const lTgtIp = lt ? lt.ip : l.target;
    return [lSrcIp, lTgtIp].sort().join('||') !== key;
  });

  const removed = before - lastTopology.links.length;
  if (removed === 0) {
    return res.status(404).json({ error: '未找到该链路' });
  }

  saveCache(lastTopology);
  console.log('[LINK/REMOVE] 删除链路: ' + source + ' <-> ' + target);

  res.json({ ok: true, removed: removed, topology: lastTopology });
});

// ============================================================

// 启动服务
// ============================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║   网络拓扑管理系统 - Node.js 后端服务        ║');
  console.log(`║   监听端口：${PORT}                            ║`);
  console.log('║   前端地址：http://localhost:8899             ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log('');
});

module.exports = app;
