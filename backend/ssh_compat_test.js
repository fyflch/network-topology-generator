const { Client } = require('ssh2');

const hosts = ['172.16.16.2', '172.16.16.254'];

async function testHost(ip) {
  return new Promise((resolve) => {
    const c = new Client();
    const t = setTimeout(() => { c.end(); resolve({ ip, result: 'TIMEOUT' }); }, 25000);

    c.on('ready', () => {
      clearTimeout(t);
      console.log(`[${ip}] SSH OK, running show version...`);
      c.exec('show version', (e, stream) => {
        if (e) { console.log(`[${ip}] exec error: ${e.message}`); c.end(); resolve({ ip, result: 'exec failed: ' + e.message }); return; }
        let out = '';
        stream.on('data', d => { out += d.toString(); });
        stream.on('close', () => {
          console.log(`[${ip}] show version (${out.length} bytes):\n${out.substring(0, 400)}\n`);
          c.end();
          resolve({ ip, result: 'OK', out: out.substring(0, 400) });
        });
        stream.stderr.on('data', d => { console.log(`[${ip}] stderr: ${d}`); });
      });
    });

    c.on('error', e => {
      clearTimeout(t);
      console.log(`[${ip}] ERR: ${e.message} | level: ${e.level}`);
      resolve({ ip, result: 'ERR: ' + e.message });
    });

    // 仅用兼容算法
    c.connect({
      host: ip, port: 22,
      username: 'admin', password: 'ruijie@123',
      readyTimeout: 20000,
      algorithms: {
        kex: [
          'diffie-hellman-group-exchange-sha1',
          'diffie-hellman-group14-sha1',
          'diffie-hellman-group1-sha1',
        ],
        cipher: [
          'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
          '3des-cbc', 'blowfish-cbc',
        ],
        serverHostKey: ['ssh-rsa', 'ssh-dss'],
        hmac: ['hmac-sha1', 'hmac-sha2-256', 'hmac-md5'],
      }
    });
  });
}

(async () => {
  for (const ip of hosts) {
    await testHost(ip);
    await new Promise(r => setTimeout(r, 1500));
  }
  process.exit(0);
})();
