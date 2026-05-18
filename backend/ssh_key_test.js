const { Client } = require('ssh2');
const fs = require('fs');
const path = require('path');

// 生成一个临时 RSA 密钥对用于测试
const { generateKeyPairSync } = require('crypto');
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  publicExponent: 0x10001,
  modulusLength: 2048,
});

const c = new Client();

c.on('ready', () => {
  console.log('SSH ready, trying exec...');
  c.exec('show version', (err, stream) => {
    if (err) { console.log('exec error:', err.message); c.end(); process.exit(1); }
    let out = '';
    stream.on('data', d => { out += d.toString(); });
    stream.on('close', () => {
      console.log('SUCCESS! Output:\n' + out.substring(0, 800));
      c.end();
      process.exit(0);
    });
  });
});

c.on('error', e => {
  console.log('ERR:', e.message);
  // Try keyboard-interactive
  console.log('Falling back to keyboard-interactive...');
});

c.on('keyboard-interactive', (name, instr, lang, prompts, finish) => {
  console.log('Keyboard-interactive prompt, name:', name);
  finish(['ruijie@123']);
});

c.connect({
  host: '172.16.16.2', port: 22,
  username: 'admin',
  // Try keyboard-interactive
  password: 'ruijie@123',
  tryKeyboard: true,
  readyTimeout: 20000,
  algorithms: {
    kex: ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
    cipher: ['aes128-cbc', 'aes256-cbc', '3des-cbc'],
    serverHostKey: ['ssh-rsa', 'ssh-dss'],
  }
});
