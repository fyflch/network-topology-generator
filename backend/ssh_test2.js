const { Client } = require('ssh2');
const c = new Client();
const t = setTimeout(() => { console.log('TIMEOUT'); c.end(); }, 20000);

c.on('ready', () => {
  console.log('SSH OK - running show version...');
  c.exec('show version', (e, stream) => {
    if (e) { console.log('exec error:', e.message); c.end(); return; }
    let out = '';
    stream.on('data', d => { out += d.toString(); });
    stream.on('close', () => {
      console.log('OUTPUT (' + out.length + ' bytes):\n' + out.substring(0, 800));
      // 立即测 LLDP
      c.exec('show lldp neighbor', (e2, s2) => {
        let o2 = '';
        s2.on('data', d => { o2 += d.toString(); });
        s2.on('close', () => {
          console.log('\nLLDP (' + o2.length + ' bytes):\n' + o2.substring(0, 600));
          c.end();
          process.exit(0);
        });
      });
    });
  });
});

c.on('error', e => {
  console.log('ERR:', e.message, '| level:', e.level);
  process.exit(1);
});

c.connect({
  host: '172.16.16.2',
  port: 22,
  username: 'admin',
  password: 'ruijie@123',
  readyTimeout: 20000,
  algorithms: {
    kex: ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
    cipher: ['aes128-cbc', 'aes256-cbc', '3des-cbc'],
    serverHostKey: ['ssh-rsa', 'ssh-dss'],
    hmac: ['hmac-sha1', 'hmac-md5'],
  }
});
