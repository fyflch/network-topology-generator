/**
 * 锐捷 SSH 连接完整调试
 * 测试多种算法组合，找出连接被重置的原因
 */
const { Client } = require('ssh2');
const net = require('net');

const hosts = [
  { ip: '172.16.16.2', port: 22 },
  { ip: '172.16.16.7', port: 22 },
  { ip: '172.16.16.51', port: 22 },
  { ip: '172.16.16.52', port: 22 },
  { ip: '172.16.16.254', port: 22 },
];
const username = 'admin';
const password = 'Admin@ruijie';

// 测试完一台再测下一台，避免并发问题
async function testHost(ip, port) {
  return new Promise((resolve) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      resolve({ ip, result: 'TIMEOUT (30s)' });
    }, 30000);

    console.log(`\n[${ip}] Connecting...`);

    conn.on('ready', () => {
      clearTimeout(timer);
      console.log(`[${ip}] SSH READY!`);
      // 先执行一条简单命令
      conn.exec('show version', (err, stream) => {
        if (err) { console.log(`[${ip}] exec error: ${err.message}`); conn.end(); resolve({ ip, result: 'exec failed: ' + err.message }); return; }
        let out = '';
        stream.on('data', d => { out += d.toString(); });
        stream.on('close', () => {
          console.log(`[${ip}] show version output (${out.length} bytes):\n${out.substring(0, 300)}`);
          conn.end();
          resolve({ ip, result: 'SUCCESS', output: out.substring(0, 300) });
        });
      });
    });

    conn.on('error', (err) => {
      clearTimeout(timer);
      console.log(`[${ip}] ERROR: ${err.message} | code=${err.code} | level=${err.level} | errno=${err.errno}`);
      resolve({ ip, result: 'ERR: ' + err.message });
    });

    conn.on('banner', (msg) => {
      console.log(`[${ip}] BANNER: ${msg.trim()}`);
    });

    // 最大兼容算法配置
    conn.connect({
      host: ip,
      port: port,
      username: username,
      password: password,
      readyTimeout: 20000,
      // 算法全开，让设备选
      algorithms: {
        kex: [
          'ecdh-sha2-nistp256',
          'ecdh-sha2-nistp384',
          'ecdh-sha2-nistp521',
          'diffie-hellman-group-exchange-sha256',
          'diffie-hellman-group14-sha256',
          'diffie-hellman-group14-sha1',
          'diffie-hellman-group1-sha1',
        ],
        cipher: [
          'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
          'aes128-cbc', 'aes256-cbc', '3des-cbc',
        ],
        serverHostKey: [
          'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512',
          'ssh-dss', 'ecdsa-sha2-nistp256',
        ],
        hmac: [
          'hmac-sha2-256', 'hmac-sha2-512',
          'hmac-sha1', 'hmac-md5',
        ],
      },
      // 不指定 agent - 用密码
    });
  });
}

async function main() {
  for (const h of hosts) {
    const r = await testHost(h.ip, h.port);
    await new Promise(r => setTimeout(r, 1000)); // 每台间隔1秒
  }
  console.log('\n=== ALL DONE ===');
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
