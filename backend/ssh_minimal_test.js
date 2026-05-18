'use strict';
const { Client } = require('ssh2');

const HOST = '172.16.16.2';
const USER = 'admin';
const PASS = 'ruijie@123';

// 极简算法配置（只留设备必然支持的）
const MINIMAL_ALGOS = {
  kex: [
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group1-sha1'
  ],
  cipher: [
    'aes128-cbc',
    'aes256-cbc',
    '3des-cbc'
  ],
  serverHostKey: [
    'ssh-rsa',
    'ssh-dss'
  ],
  hmac: [
    'hmac-sha1',
    'hmac-md5'
  ]
};

async function test(mode) {
  console.log(`\n=== ${mode} 模式测试 ===`);
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let output = '';
    const timer = setTimeout(() => {
      conn.end();
      resolve({ output, note: 'TIMEOUT, still collected ' + output.length + ' chars' });
    }, 20000);

    conn.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
      console.log('[KI] prompts:', JSON.stringify(prompts.map(p => p.prompt)));
      finish([PASS]);
    });

    conn.on('ready', () => {
      console.log('[READY] connected');
      if (mode === 'exec') {
        conn.exec('show version', (err, stream) => {
          if (err) { clearTimeout(timer); conn.end(); reject(err); return; }
          stream.on('data', d => { const s = d.toString(); output += s; process.stdout.write(s); });
          stream.stderr.on('data', d => { const s = d.toString(); output += s; process.stdout.write(s); });
          stream.on('close', () => { clearTimeout(timer); conn.end(); resolve({ output }); });
        });
      } else if (mode === 'shell-pty') {
        conn.shell({ term: 'vt100', cols: 200, rows: 50 }, (err, stream) => {
          if (err) { clearTimeout(timer); conn.end(); reject(err); return; }
          stream.on('data', d => { const s = d.toString(); output += s; process.stdout.write(s); });
          stream.on('close', () => { clearTimeout(timer); resolve({ output }); });
          setTimeout(() => {
            stream.write('show version\n');
            setTimeout(() => { stream.end(); }, 3000);
          }, 1500);
        });
      } else if (mode === 'shell-no-pty') {
        conn.shell({ term: 'vt100' }, (err, stream) => {
          if (err) { clearTimeout(timer); conn.end(); reject(err); return; }
          stream.on('data', d => { const s = d.toString(); output += s; process.stdout.write(s); });
          stream.on('close', () => { clearTimeout(timer); resolve({ output }); });
          setTimeout(() => {
            stream.write('show version\n');
            setTimeout(() => { stream.end(); }, 3000);
          }, 1500);
        });
      }
    });

    conn.on('error', err => { clearTimeout(timer); reject(err); });
    conn.connect({
      host: HOST,
      port: 22,
      username: USER,
      password: PASS,
      tryKeyboard: true,
      readyTimeout: 20000,
      algorithms: MINIMAL_ALGOS
    });
  });
}

(async () => {
  // 1. exec 模式
  try {
    const r = await test('exec');
    console.log('\n[exec OK] length:', r.output.length);
  } catch(e) {
    console.log('\n[exec FAILED]', e.message);
  }

  // 2. shell + PTY
  try {
    const r = await test('shell-pty');
    console.log('\n[shell-pty OK] length:', r.output.length);
  } catch(e) {
    console.log('\n[shell-pty FAILED]', e.message);
  }

  // 3. shell 无 PTY
  try {
    const r = await test('shell-no-pty');
    console.log('\n[shell-no-pty OK] length:', r.output.length);
  } catch(e) {
    console.log('\n[shell-no-pty FAILED]', e.message);
  }

  process.exit(0);
})();
