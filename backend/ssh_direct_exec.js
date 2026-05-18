'use strict';
const { Client } = require('ssh2');
const net = require('net');

// ── 测试1: 直接用 CHANNEL_OPEN confirmation 里的 sender channel number
// 不走 ssh2 的 exec()，而是手动发 CHANNEL_REQUEST for exec ──
async function testDirectExec() {
  console.log('\n=== 测试: 手动构造 exec request ===');
  return new Promise((resolve) => {
    const conn = new Client();
    const timer = setTimeout(() => { conn.end(); resolve({ ok: false, error: 'TIMEOUT' }); }, 12000);

    // 捕获调试信息
    conn.on('debug', msg => {
      const m = String(msg);
      if (m.includes('CHANNEL') || m.includes('REQUEST') || m.includes('OPEN') || m.includes('exec')) {
        console.log('[DBG]', m.substring(0, 200));
      }
    });

    conn.on('error', err => { clearTimeout(timer); resolve({ ok: false, error: err.message }); });

    conn.on('ready', () => {
      console.log('READY - trying direct exec...');
      
      // 直接调用 internal API: 发送 exec request
      // ssh2 的 Client.exec() 内部也是这样做，但我们可以覆盖 channel 类型
      try {
        // 尝试用不同的 channel request
        // "exec" 是 CHANNEL_REQUEST type，而不是 channel type
        // channel type 必须是 "session"，但 request type 可以是 "exec"
        
        // 用 Client.exec() 但传递 env 看看
        conn.exec('show version', (err, stream) => {
          if (err) {
            console.log('exec failed:', err.message);
            // 降级到 shell
            console.log('trying shell...');
            conn.shell({ term: 'vt100' }, (err2, s2) => {
              if (err2) { resolve({ ok: false, error: 'exec+shell failed: ' + err.message + ' / ' + err2.message }); return; }
              let out = '';
              s2.on('data', d => out += d.toString());
              s2.on('close', () => {
                console.log('shell output length:', out.length);
                resolve({ ok: out.length > 10, output: out, error: null });
              });
              setTimeout(() => { s2.write('show version\n'); }, 500);
              setTimeout(() => { s2.end(); }, 3000);
            });
            return;
          }
          let out = '';
          stream.on('data', d => { out += d.toString(); process.stdout.write(d.toString()); });
          stream.stderr.on('data', d => process.stdout.write(d.toString()));
          stream.on('close', () => {
            clearTimeout(timer);
            resolve({ ok: out.length > 10, output: out, error: null });
          });
        });
      } catch(e) {
        resolve({ ok: false, error: e.message });
      }
    });

    conn.connect({
      host: '172.16.16.2', port: 22,
      username: 'admin', password: 'ruijie@123',
      tryKeyboard: false,
      readyTimeout: 10000,
      algorithms: {
        kex: ['diffie-hellman-group14-sha1'],
        cipher: ['aes128-cbc'],
        serverHostKey: ['ssh-rsa'],
        hmac: ['hmac-sha1']
      }
    });
  });
}

// ── 测试2: 用 "subsystem" channel request（SFTP/SCP 常用）─
async function testSubsystem() {
  console.log('\n=== 测试: subsystem request ===');
  return new Promise((resolve) => {
    const conn = new Client();
    const timer = setTimeout(() => { conn.end(); resolve({ ok: false, error: 'TIMEOUT' }); }, 12000);

    conn.on('error', err => { clearTimeout(timer); resolve({ ok: false, error: err.message }); });

    conn.on('ready', () => {
      // subsystem 通常用于 SFTP，但某些设备也支持 shell via subsystem
      conn.subsystem('sftp-server', (err, stream) => {
        if (err) {
          console.log('subsystem failed:', err.message);
          clearTimeout(timer);
          resolve({ ok: false, error: 'subsystem failed: ' + err.message });
          conn.end();
          return;
        }
        console.log('subsystem opened!');
        stream.on('data', d => console.log('DATA:', d.toString().substring(0, 100)));
        stream.on('close', () => {
          clearTimeout(timer);
          resolve({ ok: true, output: 'subsystem ok', error: null });
        });
        setTimeout(() => { stream.end(); }, 2000);
      });
    });

    conn.connect({
      host: '172.16.16.2', port: 22,
      username: 'admin', password: 'ruijie@123',
      tryKeyboard: false,
      readyTimeout: 10000,
      algorithms: {
        kex: ['diffie-hellman-group14-sha1'],
        cipher: ['aes128-cbc'],
        serverHostKey: ['ssh-rsa'],
        hmac: ['hmac-sha1']
      }
    });
  });
}

// ── 测试3: 检查有没有打开 channel 的办法 ──
// 设备可能要求 CHANNEL_WINDOW_ADJUST 或特定的 channel ID 范围
async function testChannelAdjust() {
  console.log('\n=== 测试: exec + immediate window adjust ===');
  return new Promise((resolve) => {
    const conn = new Client();
    let out = '';
    const timer = setTimeout(() => { conn.end(); resolve({ ok: out.length > 10, output: out, error: 'TIMEOUT' }); }, 12000);

    conn.on('error', err => { clearTimeout(timer); resolve({ ok: false, error: err.message }); });

    conn.on('ready', () => {
      conn.exec('show version', { window: 2 * 1024 * 1024 } , (err, stream) => {
        if (err) {
          console.log('exec failed:', err.message);
          clearTimeout(timer);
          resolve({ ok: false, error: err.message });
          conn.end();
          return;
        }
        stream.on('data', d => { out += d.toString(); process.stdout.write(d.toString()); });
        stream.stderr.on('data', d => process.stdout.write(d.toString()));
        stream.on('close', () => {
          clearTimeout(timer);
          resolve({ ok: out.length > 10, output: out, error: null });
        });
      });
    });

    conn.connect({
      host: '172.16.16.2', port: 22,
      username: 'admin', password: 'ruijie@123',
      tryKeyboard: false,
      readyTimeout: 10000,
      algorithms: {
        kex: ['diffie-hellman-group14-sha1'],
        cipher: ['aes128-cbc'],
        serverHostKey: ['ssh-rsa'],
        hmac: ['hmac-sha1']
      }
    });
  });
}

// ── 测试4: 在 SSH banner 层面动手脚 ──
// 设备可能根据 SSH banner 识别客户端，伪装成 SecureCRT
async function testCRTIdent() {
  console.log('\n=== 测试: SecureCRT 伪装 banner ===');
  return new Promise((resolve) => {
    const conn = new Client();
    let out = '';
    const timer = setTimeout(() => { conn.end(); resolve({ ok: out.length > 10, output: out, error: 'TIMEOUT' }); }, 12000);

    conn.on('error', err => { clearTimeout(timer); resolve({ ok: false, error: err.message }); });

    conn.on('ready', () => {
      conn.exec('show version', (err, stream) => {
        if (err) { clearTimeout(timer); resolve({ ok: false, error: err.message }); conn.end(); return; }
        stream.on('data', d => { out += d.toString(); process.stdout.write(d.toString()); });
        stream.on('close', () => { clearTimeout(timer); resolve({ ok: out.length > 10, output: out, error: null }); });
      });
    });

    conn.connect({
      host: '172.16.16.2', port: 22,
      username: 'admin', password: 'ruijie@123',
      // SecureCRT 使用的 banner 格式
      // 实际 SecureCRT 会发送不同的客户端标识
      // 尝试 OpenSSH 标识（CRT 也常用）
      ident: 'SSH-2.0-OpenSSH_7.4',
      tryKeyboard: false,
      readyTimeout: 10000,
      algorithms: {
        kex: ['diffie-hellman-group14-sha1'],
        cipher: ['aes128-cbc'],
        serverHostKey: ['ssh-rsa'],
        hmac: ['hmac-sha1']
      }
    });
  });
}

(async () => {
  console.log('=== SSH channel 类型测试 ===\n');
  console.log('目标: 172.16.16.2');
  console.log('确认: 密码认证成功，但 CHANNEL_OPEN (session) 被拒绝\n');

  const results = [];

  results.push(await testDirectExec());
  await new Promise(r => setTimeout(r, 3000));

  results.push(await testSubsystem());
  await new Promise(r => setTimeout(r, 3000));

  results.push(await testChannelAdjust());
  await new Promise(r => setTimeout(r, 3000));

  results.push(await testCRTIdent());
  await new Promise(r => setTimeout(r, 3000));

  console.log('\n\n=== 结果汇总 ===');
  results.forEach((r, i) => {
    const names = ['exec+shell降级', 'subsystem', 'window扩大', 'CRT标识'];
    if (r.ok) {
      console.log(`✅ ${names[i]}: 成功`);
    } else {
      console.log(`❌ ${names[i]}: ${r.error}`);
    }
  });
  process.exit(0);
})();
