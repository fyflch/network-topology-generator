'use strict';
const { Client } = require('ssh2');

const HOST = '172.16.16.2';
const USER = 'admin';
const PASS = 'ruijie@123';

async function test(label, opts) {
  return new Promise((resolve) => {
    const conn = new Client();
    let timedout = false;
    const timer = setTimeout(() => {
      timedout = true;
      conn.end();
      resolve({ label, ok: false, error: 'TIMEOUT' });
    }, 15000);

    conn.on('error', err => {
      if (timedout) return;
      clearTimeout(timer);
      resolve({ label, ok: false, error: err.message });
    });
    conn.on('close', () => {
      if (timedout) return;
      clearTimeout(timer);
    });

    conn.on('ready', () => {
      console.log(`[${label}] ready`);
      // 根据模式发送不同请求
      if (opts.mode === 'exec-pty') {
        conn.exec('show version', { pty: true }, (err, stream) => {
          if (err) { resolve({ label, ok: false, error: 'exec:' + err.message }); conn.end(); return; }
          let out = '';
          stream.on('data', d => out += d.toString());
          stream.stderr.on('data', d => out += d.toString());
          stream.on('close', () => { conn.end(); resolve({ label, ok: out.length > 20, output: out.substring(0, 200), error: null }); });
        });
      } else if (opts.mode === 'shell') {
        conn.shell({ term: 'xterm', cols: 200, rows: 40 }, (err, stream) => {
          if (err) { resolve({ label, ok: false, error: 'shell:' + err.message }); conn.end(); return; }
          let out = '';
          stream.on('data', d => out += d.toString());
          stream.on('close', () => { conn.end(); resolve({ label, ok: out.length > 20, output: out.substring(0, 200), error: null }); });
          // 发送命令
          setTimeout(() => stream.write('show version\n'), 1000);
          setTimeout(() => stream.end(), 3000);
        });
      } else if (opts.mode === 'exec') {
        conn.exec('show version', (err, stream) => {
          if (err) { resolve({ label, ok: false, error: 'exec:' + err.message }); conn.end(); return; }
          let out = '';
          stream.on('data', d => out += d.toString());
          stream.stderr.on('data', d => out += d.toString());
          stream.on('close', () => { conn.end(); resolve({ label, ok: out.length > 20, output: out.substring(0, 200), error: null }); });
        });
      }
    });

    conn.connect({
      host: HOST,
      port: 22,
      username: USER,
      password: PASS,
      readyTimeout: 15000,
      algorithms: {
        kex: ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
        cipher: ['aes128-cbc', 'aes256-cbc', '3des-cbc'],
        serverHostKey: ['ssh-rsa', 'ssh-dss'],
        hmac: ['hmac-sha1', 'hmac-md5']
      },
      ...opts.connect
    });
  });
}

(async () => {
  const results = [];

  // 测试1: exec 默认（无PTY）
  results.push(await test('exec-no-pty', { mode: 'exec', connect: {} }));
  await new Promise(r => setTimeout(r, 2000));

  // 测试2: exec + PTY
  results.push(await test('exec-with-pty', { mode: 'exec-pty', connect: {} }));
  await new Promise(r => setTimeout(r, 2000));

  // 测试3: shell
  results.push(await test('shell-pty', { mode: 'shell', connect: {} }));
  await new Promise(r => setTimeout(r, 2000));

  console.log('\n\n=== 结果汇总 ===');
  results.forEach(r => {
    if (r.ok) {
      console.log(`✅ ${r.label}: 成功 (${r.output.length}字节)`);
    } else {
      console.log(`❌ ${r.label}: ${r.error}`);
    }
  });
  process.exit(0);
})();
