'use strict';
// 测试修复后的 SSH 连接（加载 server.js 中的函数）
const path = require('path');
const fs = require('fs');

// 直接复制算法配置和函数来测试
const SSH_ALGORITHMS = {
  kex: [
    'ecdh-sha2-nistp256','ecdh-sha2-nistp384','ecdh-sha2-nistp521',
    'diffie-hellman-group14-sha256','diffie-hellman-group16-sha512',
    'diffie-hellman-group18-sha512',
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group1-sha1'
  ],
  cipher: [
    'aes128-ctr','aes192-ctr','aes256-ctr',
    'aes128-gcm@openssh.com','aes256-gcm@openssh.com',
    'aes128-cbc','aes192-cbc','aes256-cbc',
    '3des-cbc'
  ],
  serverHostKey: [
    'ssh-rsa','rsa-sha2-256','rsa-sha2-512',
    'ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521',
    'ssh-ed25519','ssh-dss'
  ],
  hmac: [
    'hmac-sha2-256','hmac-sha2-512',
    'hmac-sha1','hmac-sha1-96',
    'hmac-md5','hmac-md5-96'
  ]
};

const { Client } = require('ssh2');

function sshShellTest(host, port, username, password, commands, timeout) {
  timeout = timeout || 20000;
  if (!Array.isArray(commands)) commands = [commands];
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let output = '';
    const timer = setTimeout(() => {
      try{ conn.end(); }catch(_){}
      if (output.length > 50) resolve({ output, error: '' });
      else reject(new Error('Shell 会话超时，已收集 ' + output.length + ' 字节'));
    }, timeout);

    // ── keyboard-interactive 必须在 connect() 之前注册 ──
    conn.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
      console.log('[KI] prompts:', prompts.map(p => p.prompt).join(', '));
      finish([password]);
    });

    conn.on('ready', () => {
      console.log('[SSH] ready, opening shell...');
      conn.shell({ term: 'vt100', cols: 200, rows: 50 }, (err, stream) => {
        if (err) { clearTimeout(timer); conn.end(); reject(err); return; }

        stream.on('data', (d) => {
          const s = d.toString();
          output += s;
          process.stdout.write(s);
        });
        stream.stderr.on('data', (d) => { output += d.toString(); });

        let cmdIdx = 0;
        function sendNext() {
          if (cmdIdx < commands.length) {
            const cmd = commands[cmdIdx++];
            console.log('\n[SEND]', cmd);
            stream.write(cmd + '\n');
            setTimeout(sendNext, 1500);
          } else {
            setTimeout(() => {
              clearTimeout(timer);
              try{ stream.end(); conn.end(); }catch(_){}
              resolve({ output, error: '' });
            }, 2000);
          }
        }
        setTimeout(sendNext, 1500);
      });
    });

    conn.on('error', (err) => { clearTimeout(timer); reject(err); });
    conn.connect({
      host, port: port || 22, username, password,
      readyTimeout: 20000,
      algorithms: SSH_ALGORITHMS,
      tryKeyboard: true
    });
  });
}

// ── 主测试 ──
(async () => {
  const HOST = '172.16.16.2';
  const USER = 'admin';
  const PASS = 'ruijie@123';

  console.log('=== 测试 SSH shell 模式（修复后）===\n');
  console.log('Host:', HOST);
  console.log('User:', USER);
  console.log('Algorithms: kex =', SSH_ALGORITHMS.kex.join(', '));
  console.log('');

  try {
    const r = await sshShellTest(HOST, 22, USER, PASS, [
      'terminal length 0',
      'show version',
      'show lldp neighbors'
    ], 25000);
    console.log('\n\n=== SUCCESS ===');
    console.log('输出长度:', r.output.length);
    // 提取关键信息
    const ver = r.output.match(/Ruijie.*?Version[:\s]+([^\n]+)/i);
    if (ver) console.log('版本:', ver[1]);
    const lldp = r.output.match(/([\w\-]+)\s+(\w+)\s+(\w+)/g);
    if (lldp) console.log('LLDP 行:', lldp.slice(0, 5).join('\n'));
  } catch (e) {
    console.log('\n=== FAILED ===');
    console.log('Error:', e.message);
    process.exit(1);
  }
})();
