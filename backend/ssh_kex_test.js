const { Client } = require('ssh2');

// 拦截 DEBUG 事件获取服务端支持的算法
const c = new Client();
let debugOutput = '';

c.on('debug', (msg) => {
  debugOutput += msg + '\n';
  // 打印与服务端算法选择相关的信息
  if (msg.includes('KEX') || msg.includes('kex') || msg.includes('CLIENT') || msg.includes('SERVER')) {
    console.log('[DEBUG]', msg);
  }
});

c.on('error', e => {
  console.log('ERROR:', e.message);
  console.log('\n--- DEBUG OUTPUT ---');
  console.log(debugOutput.substring(0, 3000));
  process.exit(1);
});

c.on('ready', () => {
  console.log('\n*** SSH READY ***');
  console.log('\n--- DEBUG OUTPUT ---');
  console.log(debugOutput.substring(0, 3000));
  c.end();
  process.exit(0);
});

// 测试不同的 KEX 算法组合
const testCases = [
  { name: 'all_old', kex: ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1'] },
  { name: 'sha1_only', kex: ['diffie-hellman-group14-sha1'] },
  { name: 'sha1_group1', kex: ['diffie-hellman-group1-sha1'] },
];

async function runTests() {
  for (const tc of testCases) {
    console.log(`\n=== Testing ${tc.name} ===`);
    await new Promise((resolve) => {
      const cc = new Client();
      const tt = setTimeout(() => { cc.end(); console.log('TIMEOUT'); resolve(); }, 15000); cc.on('error', e => { clearTimeout(tt); console.log(`ERR(${tc.name}): ${e.message}`); resolve(); });
      cc.on('ready', () => { clearTimeout(tt); console.log(`OK(${tc.name}): SSH READY`); cc.end(); resolve(); });
      cc.connect({ host: '172.16.16.2', port: 22, username: 'admin', password: 'ruijie@123', readyTimeout: 12000, algorithms: { kex: tc.kex, cipher: ['aes128-cbc', '3des-cbc'], serverHostKey: ['ssh-rsa', 'ssh-dss'] } });
    });
    await new Promise(r => setTimeout(r, 1000));
  }
  process.exit(0);
}

runTests();
