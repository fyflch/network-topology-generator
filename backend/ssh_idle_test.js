'use strict';
const { Client } = require('ssh2');

const HOST = '172.16.16.2';
const USER = 'admin';
const PASS = 'ruijie@123';

async function testIdle() {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let stage = 'init';

    conn.on('ready', () => {
      stage = 'ready';
      console.log('[READY] 连接成功，不打开channel，等待10秒...');
      // 等待 10 秒，不做任何事
      setTimeout(() => {
        stage = 'closing';
        console.log('[CLOSE] 主动关闭连接');
        conn.end();
      }, 10000);
    });

    conn.on('error', err => {
      console.log(`[ERROR] stage=${stage} err=${err.message}`);
      reject({ stage, error: err.message });
    });

    conn.on('close', (hadError) => {
      console.log(`[CLOSE] stage=${stage} hadError=${hadError}`);
      if (stage === 'closing' || stage === 'ready') {
        resolve({ ok: true, stage });
      } else {
        reject({ ok: false, stage, error: 'closed before ready' });
      }
    });

    conn.connect({
      host: HOST,
      port: 22,
      username: USER,
      password: PASS,
      tryKeyboard: false,
      readyTimeout: 15000,
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
  console.log('=== 测试：连接后不打开channel ===\n');
  try {
    const r = await testIdle();
    console.log('\n✅ 成功！没有 ECONNRESET');
    console.log('说明问题在 channel 打开阶段');
  } catch (e) {
    console.log('\n❌ 失败:', JSON.stringify(e));
    if (e.stage === 'ready') {
      console.log('连接成功，但在空闲时断开 → 设备有超时断开机制');
    } else {
      console.log('连接阶段就失败了');
    }
  }
  process.exit(0);
})();
