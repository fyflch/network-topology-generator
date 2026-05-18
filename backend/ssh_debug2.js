'use strict';
const { Client } = require('ssh2');

const c = new Client();
let done = false;
const t = setTimeout(() => {
  if (!done) { c.end(); console.log('TIMEOUT'); process.exit(0); }
}, 15000);

const ALL_EVENTS = [];
function addEvt(name, data) {
  const line = `[${Date.now()}] ${name}: ${JSON.stringify(data||'').substring(0,200)}`;
  ALL_EVENTS.push(line);
  // 打印关键事件
  if (name.startsWith('ready') || name.startsWith('error') || name.startsWith('EXEC') || 
      name.startsWith('CLOSE') || name.startsWith('GEX') || name.startsWith('CHANNEL') ||
      name.startsWith('AUTH') || name.startsWith('KEXINIT') || name.startsWith('SERVICE') ||
      name.startsWith('OPEN') || name.startsWith('DEBUG')) {
    console.log(line);
  }
}

// 监听所有事件
const evts = ['ready','error','close','end','keyboard-interactive','password','hostkeys',
              'authenticating','authenticate','rekey','request'];
evts.forEach(e => c.on(e, d => addEvt(e, d)));

c.on('error', e => addEvt('ERROR', e.message));
c.on('close', () => addEvt('CLOSE', ''));
c.on('ready', () => {
  addEvt('*** READY ***', '');
  console.log('\n=== READY! Opening exec channel... ===\n');
  c.exec('show version', (err, stream) => {
    if (err) {
      addEvt('EXEC ERR', err.message);
      console.log('exec failed:', err.message);
      c.end();
      return;
    }
    addEvt('EXEC OK', 'channel opened');
    let out = '';
    stream.on('data', d => { out += d.toString(); process.stdout.write(d.toString()); });
    stream.stderr.on('data', d => process.stdout.write('[ERR]' + d.toString()));
    stream.on('close', (code, sig) => {
      addEvt('STREAM CLOSE', `code=${code} sig=${sig}`);
      console.log('\n=== 输出长度:', out.length, '===');
      if (out.length > 0) {
        console.log('SUCCESS!');
      } else {
        console.log('No output received');
      }
      c.end();
      done = true;
      clearTimeout(t);
      process.exit(0);
    });
  });
});

c.on('keyboard-interactive', (name, instr, lang, prompts, finish) => {
  addEvt('KI', prompts.map(p=>p.prompt));
  finish(['ruijie@123']);
});

// 连接配置
const connOpts = {
  host: '172.16.16.2',
  port: 22,
  username: 'admin',
  password: 'ruijie@123',
  tryKeyboard: false,
  readyTimeout: 10000,
  algorithms: {
    kex: ['diffie-hellman-group14-sha1'],
    cipher: ['aes128-cbc'],
    serverHostKey: ['ssh-rsa'],
    hmac: ['hmac-sha1']
  },
  debug: (msg) => {
    const m = String(msg);
    // 打印协议协商关键信息
    if (m.includes('GEX') || m.includes('KEX') || m.includes('SERVICE') || 
        m.includes('AUTH') || m.includes('CHANNEL') || m.includes('OPEN') ||
        m.includes('exec') || m.includes('request') || m.includes('SESSION') ||
        m.includes('window') || m.includes('packet') || m.includes('disconnect') ||
        m.includes('METHOD') || m.includes('PROTO') || m.includes('FAILURE')) {
      addEvt('DEBUG', m.substring(0, 200));
      console.log('[DBG]', m.substring(0, 200));
    }
  }
};

console.log('Connecting to 172.16.16.2 with minimal algorithms...');
c.connect(connOpts);
