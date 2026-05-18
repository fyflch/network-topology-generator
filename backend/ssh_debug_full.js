'use strict';
const { Client } = require('ssh2');
const fs = require('fs');

const HOST = '172.16.16.2';
const USER = 'admin';
const PASS = 'ruijie@123';

const logFile = 'ssh_debug.log';
fs.writeFileSync(logFile, ''); // 清空日志

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  fs.appendFileSync(logFile, line);
  process.stdout.write(line);
}

(async () => {
  log('=== SSH 完整协议调试 ===');
  
  const conn = new Client();

  // 捕获所有事件
  ['ready', 'error', 'close', 'end', 'finish', 'drain', 'timeout', 'data'].forEach(ev => {
    conn.on(ev, (...args) => {
      log(`EVENT: ${ev} ${JSON.stringify(args).substring(0, 200)}`);
    });
  });

  conn.on('ready', () => {
    log('*** READY fired, now trying exec...');
    
    // 用 setTimeout 确保我们能在 exec 之前捕获到任何协议交换
    setTimeout(() => {
      log('Calling conn.exec("show version")...');
      conn.exec('show version', (err, stream) => {
        if (err) {
          log(`exec callback ERROR: ${err.message}`);
          conn.end();
          return;
        }
        log('exec callback: stream opened');
        let out = '';
        stream.on('data', d => { out += d.toString(); log('STDOUT: ' + d.toString().substring(0, 80)); });
        stream.stderr.on('data', d => { log('STDERR: ' + d.toString().substring(0, 80)); });
        stream.on('close', () => { log('STREAM CLOSE'); conn.end(); });
      });
    }, 100); // 延迟 100ms 让协议层稳定
  });

  conn.on('error', (err) => {
    log(`ERROR: ${err.message} (level=${err.level}, code=${err.code})`);
  });

  log('Connecting...');
  conn.connect({
    host: HOST,
    port: 22,
    username: USER,
    password: PASS,
    tryKeyboard: false,
    readyTimeout: 20000,
    algorithms: {
      kex: ['diffie-hellman-group14-sha1'],
      cipher: ['aes128-cbc'],
      serverHostKey: ['ssh-rsa'],
      hmac: ['hmac-sha1']
    },
    // 关键：开启所有 debug 输出
    debug: (info) => {
      const msg = String(info);
      // 过滤掉太长的包数据，只保留关键信息
      if (msg.includes('[DBG]') || msg.includes('KEX') || msg.includes('AUTH') ||
          msg.includes('SERVICE') || msg.includes('CHANNEL') || msg.includes('REQUEST') ||
          msg.includes('OPEN') || msg.includes('FAIL') || msg.includes('WIN') ||
          msg.includes('GEX') || msg.includes('NEWKEYS')) {
        log('DBG: ' + msg.substring(0, 300));
      }
    }
  });

  // 等待结果
  await new Promise(r => setTimeout(r, 15000));
  log('=== 调试结束，查看 ' + logFile + ' ===');
  process.exit(0);
})();
