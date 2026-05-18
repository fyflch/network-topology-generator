'use strict';
const { Client } = require('ssh2');

const HOST = '172.16.16.2';
const USER = 'admin';
const PASS = 'ruijie@123';

// 完整事件监控，看 ECONNRESET 前最后发生了什么
async function debugSession() {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const events = [];
    let timer;

    function log(event, data) {
      const entry = `[${new Date().toISOString()}] ${event} ${JSON.stringify(data || '')}`.substring(0, 200);
      events.push(entry);
      console.log(entry);
    }

    timer = setTimeout(() => {
      conn.end();
      resolve({ events, note: 'timeout' });
    }, 20000);

    conn.on('debug', msg => {
      // 只关注 SSH 协议层面的消息
      const m = String(msg);
      if (m.includes('GEX') || m.includes('auth') || m.includes('service') ||
          m.includes('channel') || m.includes('request') || m.includes('SESSION') ||
          m.includes('openssh') || m.includes('cipher') || m.includes('算法的')) {
        log('DEBUG', m.substring(0, 150));
      }
    });

    ['error', 'close', 'end', 'keyboard-interactive', 'password', 
     'hostkeys', 'authenticate', 'ready', 'reconnect', 'packet'].forEach(ev => {
      conn.on(ev, (data) => {
        if (ev === 'packet') {
          // Don't log every packet - too verbose
          return;
        }
        log('EVENT: ' + ev, data ? String(data).substring(0, 100) : '');
      });
    });

    conn.on('error', (err) => {
      clearTimeout(timer);
      console.log('\n!!! ERROR:', err.message, err.level);
      // 打印最近的事件
      console.log('\n--- 最后 20 条事件 ---');
      events.slice(-20).forEach(e => console.log(e));
      reject(err);
    });

    conn.on('ready', () => {
      log('*** READY ***', '');
      console.log('\nconnection ready, trying exec...');
      
      // 用 exec 方式
      conn.exec('show version', (err, stream) => {
        if (err) {
          log('EXEC ERROR', err.message);
          clearTimeout(timer);
          conn.end();
          console.log('\n--- 所有事件 ---');
          events.forEach(e => console.log(e));
          reject(err);
          return;
        }
        log('STREAM opened', '');
        let out = '';
        stream.on('data', d => {
          out += d.toString();
          // 实时打印
          const lines = d.toString().split('\n');
          lines.forEach(l => { if (l.trim()) console.log('STDOUT:', l.substring(0, 120)); });
        });
        stream.stderr.on('data', d => {
          const lines = d.toString().split('\n');
          lines.forEach(l => { if (l.trim()) console.log('STDERR:', l.substring(0, 120)); });
        });
        stream.on('close', (code, signal) => {
          clearTimeout(timer);
          log('STREAM CLOSE', `code=${code} signal=${signal}`);
          console.log('\n=== 成功! 输出长度: ' + out.length + ' ===');
          conn.end();
          resolve({ out, events });
        });
      });
    });

    console.log('Connecting to', HOST, '...');
    conn.connect({
      host: HOST,
      port: 22,
      username: USER,
      password: PASS,
      tryKeyboard: false,    // 先只用密码
      readyTimeout: 20000,
      algorithms: {
        kex: ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
        cipher: ['aes128-cbc', 'aes256-cbc', '3des-cbc'],
        serverHostKey: ['ssh-rsa', 'ssh-dss'],
        hmac: ['hmac-sha1', 'hmac-md5']
      }
    });
  });
}

debugSession()
  .then(r => console.log('\n最终输出:\n', r.out.substring(0, 500)))
  .catch(e => console.log('\n失败:', e.message));
