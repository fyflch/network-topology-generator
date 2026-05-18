/**
 * 网络拓扑管理系统 - Node.js 后端 API
 * 支持 SSH 登录交换机、采集 LLDP/SNMP 数据、生成拓扑图
 */

'use strict';

const express = require('express');
const cors = require('cors');
const { Client } = require('ssh2');
const snmp = require('net-snmp');
const net = require('net');
const os = require('os');
const path = require('path');

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

  // 中兴
  if (combined.includes('zte') || combined.includes('zxr')) return 'zte';

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
  if (p.includes('100ge') || p.includes('hundredgig')) return { type: '100G 光纤', speed: '100Gbps' };
  if (p.includes('40g') || p.includes('fortygig'))    return { type: '40G 光纤', speed: '40Gbps' };
  if (p.includes('25g'))                               return { type: '25G 光纤', speed: '25Gbps' };
  if (p.includes('tengig') || p.includes('10ge') || p.includes('xg')) {
    return { type: '万兆光纤', speed: '10Gbps' };
  }
  if (p.includes('lag') || p.includes('eth-trunk') || p.includes('port-channel') || p.includes('agg') || p.includes('po')) {
    return { type: 'LAG 聚合', speed: '聚合链路' };
  }
  if (p.includes('gig') || p.includes('ge') || p.includes('gi')) {
    return { type: '千兆以太网', speed: '1Gbps' };
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
      '1.3.6.1.2.1.1.4.0'   // sysContact
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
      // 至少有一个字段有值才算成功
      if (!result.sysDescr && !result.sysName) { resolve(null); return; }
      resolve(result);
    });
  });
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
    const fields = [
      { name: 'chassisId',  oid: base + '.5' },
      { name: 'portId',     oid: base + '.7' },
      { name: 'portDesc',   oid: base + '.8' },
      { name: 'sysName',    oid: base + '.9' },
      { name: 'sysDesc',    oid: base + '.10' },
      { name: 'localPort',  oid: base + '.3' },
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
              // 本地端口：先从 ifDescr 查，再 fallback
              const localPort = ifDescrMap[n._localIfIdx]
                || n.localPort
                || `GigabitEthernet 0/${n._localIfIdx}`;
              // 远端端口：portDesc 是最可读的端口名（如 GigabitEthernet 0/48）
              const remotePort = n.portDesc || n.portId || '';
              neighbors.push({
                neighborId,
                localPort,                   // ifDescr 字符串，如 "TenGigabitEthernet 1/48"
                localIfIdx: n._localIfIdx,   // 纯数字 ifIndex，如 "48"（用于查 ifSpeedMap）
                portDesc: remotePort,
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
        // SNMP 识别厂商（最准确）
        const snmpVendor = detectVendor('', device.snmp.sysDescr || '');
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
    const sshVendor = detectVendor(shellOut, device.snmp ? device.snmp.sysDescr : '');
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
        // 将 SNMP 邻居格式统一为与 SSH LLDP 相同的字段名
        // 关键：localIfIdx 是纯数字 ifIndex（用于查 ifSpeedMap）
        //       localPort 是 ifDescr 字符串（用于显示）
        const converted = snmpNeighbors.map(n => {
          const ifIdx = n.localIfIdx || '';
          const bps = device.ifSpeedMap[ifIdx] || 0;
          return {
            local_port:  n.localPort  || ifIdx,  // 优先用 ifDescr 字符串（显示用）
            local_speed: bps > 0 ? _formatBps(bps, n.localPort) : '',
            remote_name: n.sysName    || n.neighborId || 'Unknown',
            remote_port: n.portId     || n.portDesc   || '',
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
      vendor: d.vendor,
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

      // guessLinkType(portName) 不再接收 sys_desc，避免交换机型号字符串误判速率
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

    // 第一阶段：TCP 探测
    scanStatus.message = `TCP 探测中... (0/${ips.length})`;
    let probed = 0;

    for (let i = 0; i < ips.length; i += maxConcur) {
      const batch = ips.slice(i, i + maxConcur);
      const results = await Promise.all(batch.map(ip => tcpProbe(ip, ssh_port || 22, 1500)));
      results.forEach((ok, j) => {
        if (ok) reachable.push(batch[j]);
        probed++;
      });
      scanStatus.progress = Math.round((probed / ips.length) * 40);
      scanStatus.message = `TCP 探测中... (${probed}/${ips.length})，在线: ${reachable.length}`;
    }

    if (reachable.length === 0) {
      scanStatus = { running: false, progress: 100, message: '未发现在线设备', total: ips.length, done: ips.length, found: 0 };
      lastTopology = { nodes: [], links: [] };
      return;
    }

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
