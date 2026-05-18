'use strict';
const { Client } = require('ssh2');

const HOST = '172.16.16.2';
const USER = 'admin';
const PASS = 'ruijie@123';

// 伪装客户端标识为常见 SSH 客户端
const CLIENT_IDENTS = [
  'SSH-2.0-OpenSSH_7.4',      // 最常见
  'SSH-2.0-OpenSSH_8.0',
  'SSH-2.0-PuTTY_Release_0.76', // PuTTY，与CRT同源
  'SSH-2.0-OpenSSH',
  '',  // 默认 ssh2js 标识
];

async function testIdent(ident) {
  return new Promise((resolve) => {
    const conn = new Client();
    let output = '';
    const timer = setTimeout(() => { conn.end(); resolve({ ok: false, ident, error: 'TIMEOUT' }); }, 15000);

    conn.on('ready', () => {
      console.log(`  [${ident || 'default'}] ready -> trying exec...`);
      conn.exec('show version', (err, stream) => {
        if (err) { clearTimeout(timer); conn.end(); resolve({ ok: false, ident, error: 'exec:' + err.message }); return; }
        stream.on('data', d => output += d.toString());
        stream.stderr.on('data', d => output += d.toString());
        stream.on('close', () => {
          clearTimeout(timer);
          conn.end();
          resolve({ ok: output.length > 20, ident, output: output.substring(0, 100), error: null });
        });
      });
    });

    conn.on('error', err => { clearTimeout(timer); resolve({ ok: false, ident, error: err.message }); });
    conn.on('close', () => { clearTimeout(timer); });

    const config = {
      host: HOST,
      port: 22,
      username: USER,
      password: PASS,
      readyTimeout: 10000,
      algorithms: {
        kex: ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
        cipher: ['aes128-cbc', '3des-cbc'],
        serverHostKey: ['ssh-rsa', 'ssh-dss'],
        hmac: ['hmac-sha1']
      }
    };
    if (ident) config.ident = ident;
    conn.connect(config);
  });
}

(async () => {
  console.log('=== 测试不同客户端标识 ===\n');

  for (const ident of CLIENT_IDENTS) {
    const label = ident || 'default(ssh2js)';
    console.log(`测试: ${label}`);
    const r = await testIdent(ident);
    if (r.ok) {
      console.log(`  ✅ 成功！输出: ${r.output.replace(/\n/g, ' ').substring(0, 80)}`);
    } else {
      console.log(`  ❌ 失败: ${r.error}`);
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  process.exit(0);
})();
