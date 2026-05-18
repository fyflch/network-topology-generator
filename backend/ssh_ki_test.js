'use strict';
const { Client } = require('ssh2');

const HOST = '172.16.16.2';
const USER = 'admin';
const PASS = 'ruijie@123';

console.log(`Testing SSH -> ${HOST} with keyboard-interactive auth...\n`);

const conn = new Client();

conn.on('ready', () => {
  console.log('[READY] Connection established');

  // Try exec first
  conn.exec('show version', (err, stream) => {
    if (err) {
      console.log('[EXEC error]', err.message);
      // Try shell as fallback
      conn.shell((err2, stream2) => {
        if (err2) { console.log('[SHELL error]', err2.message); conn.end(); return; }
        let out = '';
        stream2.on('data', d => { out += d.toString(); process.stdout.write(d.toString()); });
        stream2.on('close', () => { console.log('\n[SHELL close]'); conn.end(); });
        setTimeout(() => stream2.write('show version\n'), 500);
        setTimeout(() => stream2.end(), 3000);
      });
      return;
    }
    let out = '', errOut = '';
    stream.on('data', d => { out += d.toString(); process.stdout.write(d.toString()); });
    stream.stderr.on('data', d => { errOut += d.toString(); process.stdout.write(d.toString()); });
    stream.on('close', (code) => {
      console.log('\n[EXEC close] code:', code);
      conn.end();
    });
  });
})
.on('error', err => {
  console.log('[ERROR]', err.message, err.level || '');
})
.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
  console.log('[KI] name:', name);
  console.log('[KI] prompts:', JSON.stringify(prompts));
  // Answer each prompt with the password
  finish([PASS]);
})
.connect({
  host: HOST,
  port: 22,
  username: USER,
  // Use keyboard-interactive explicitly
  tryKeyboard: true,
  // Also try password fallback
  password: PASS,
  readyTimeout: 20000,
  debug: console.log.bind(console, '[DBG]'),
});
