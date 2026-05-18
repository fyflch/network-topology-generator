'use strict';
const { Client } = require('ssh2');

async function test(label, opts) {
  return new Promise((resolve) => {
    const conn = new Client();
    let out = '';
    const t = setTimeout(() => { try { conn.end(); } catch(_) {} resolve({ ok: false, label, error: 'TIMEOUT' }); }, 15000);

    conn.on('error', err => { clearTimeout(t); resolve({ ok: false, label, error: err.message }); });
    conn.on('ready', () => {
      // 根据不同模式
      if (opts.type === 'exec') {
        conn.exec('show version', opts.execOpts || {}, (err, stream) => {
          if (err) { clearTimeout(t); conn.end(); resolve({ ok: false, label, error: 'exec: ' + err.message }); return; }
          stream.on('data', d => out += d.toString());
          stream.stderr.on('data', d => out += d.toString());
          stream.on('close', () => { clearTimeout(t); conn.end(); resolve({ ok: out.length > 10, label, output: out.substring(0,100), error: null }); });
        });
      } else if (opts.type === 'shell') {
        conn.shell(opts.shellOpts || {}, (err, stream) => {
          if (err) { clearTimeout(t); conn.end(); resolve({ ok: false, label, error: 'shell: ' + err.message }); return; }
          stream.on('data', d => out += d.toString());
          stream.on('close', () => { clearTimeout(t); conn.end(); resolve({ ok: out.length > 10, label, output: out.substring(0,100), error: null }); });
          setTimeout(() => stream.write('show version\n'), 800);
          setTimeout(() => { stream.end(); }, 4000);
        });
      } else if (opts.type === 'direct') {
        // 尝试直接 TCP 转发（不走 session channel）
        // 这个会在设备上建立 TCP 连接到本地
        console.log('  trying direct-tcpip...');
        resolve({ ok: false, label, error: 'direct-tcpip skipped' });
      }
    });

    const connOpts = {
      host: '172.16.16.2', port: 22,
      username: 'admin', password: 'ruijie@123',
      tryKeyboard: false,
      readyTimeout: 12000,
      algorithms: {
        kex: ['diffie-hellman-group14-sha1'],
        cipher: ['aes128-cbc'],
        serverHostKey: ['ssh-rsa'],
        hmac: ['hmac-sha1']
      },
      ...(opts.connect || {})
    };
    conn.connect(connOpts);
  });
}

(async () => {
  console.log('=== SSH Channel Workaround 测试 ===\n');
  const tests = [
    // 1. exec + keepalive
    { label: 'exec+keepalive', opts: { type: 'exec', execOpts: { pty: false }, connect: { keepaliveInterval: 1000, keepaliveCountMax: 3 } } },
    // 2. exec 不带任何选项
    { label: 'exec裸', opts: { type: 'exec' } },
    // 3. shell 不带 PTY
    { label: 'shell无pty', opts: { type: 'shell', shellOpts: {} } },
    // 4. shell + pty
    { label: 'shell+pty', opts: { type: 'shell', shellOpts: { term: 'vanilla' } } },
    // 5. 禁用 ext_info (某些设备不喜欢)
    { label: '无ext-info', opts: { type: 'exec', connect: { compress: false } } },
    // 6. 伪造成特定banner
    { label: 'SecureCRTbanner', opts: { type: 'exec', connect: { ident: 'SSH-2.0-OpenSSH_7.2' } } },
    // 7. 不发 kex-strict
    { label: '无strictKEX', opts: { type: 'exec', connect: { 
      algorithms: { kex: ['diffie-hellman-group14-sha1'], cipher: ['aes128-cbc'], serverHostKey: ['ssh-rsa'], hmac: ['hmac-sha1'] }
    } } },
  ];

  const results = [];
  for (const t of tests) {
    console.log(`\n测试: ${t.label}`);
    const r = await test(t.label, t.opts);
    results.push(r);
    if (r.ok) {
      console.log(`  ✅ 成功: ${r.output}`);
    } else {
      console.log(`  ❌ ${r.error}`);
    }
    await new Promise(r => setTimeout(r, 3000));
  }

  console.log('\n\n=== 结果 ===');
  results.forEach(r => {
    console.log(r.ok ? `✅ ${r.label}` : `❌ ${r.label}: ${r.error}`);
  });
  process.exit(0);
})();
