const { Client } = require('ssh2');

const c = new Client();
const t = setTimeout(() => { c.end(); console.log('TIMEOUT'); process.exit(1); }, 30000);

c.on('ready', () => {
  console.log('SSH ready, requesting PTY...');
  c.shell({ term: 'vt100', cols: 200, rows: 40 }, (err, stream) => {
    if (err) {
      console.log('shell(pty) error:', err.message);
      // fallback: try exec
      console.log('Fallback: trying exec without pty...');
      c.exec('show version', (e, s) => {
        if (e) { console.log('exec error:', e.message); c.end(); return; }
        let out = '';
        s.on('data', d => { out += d.toString(); });
        s.on('close', () => {
          console.log('exec output:\n' + out.substring(0, 600));
          c.end();
          process.exit(0);
        });
      });
      return;
    }

    let out = '';
    stream.on('data', d => { out += d.toString(); });
    stream.on('close', () => {
      console.log('Shell output:\n' + out.substring(0, 800));
      c.end();
      process.exit(0);
    });

    setTimeout(() => {
      stream.write('show version\n');
      setTimeout(() => {
        stream.write('show lldp neighbor\n');
        setTimeout(() => { stream.write('exit\n'); stream.end(); }, 5000);
      }, 3000);
    }, 2000);
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
    kex: [
      'ecdh-sha2-nistp256',
      'diffie-hellman-group14-sha256',
      'diffie-hellman-group14-sha1',
      'diffie-hellman-group-exchange-sha256',
      'diffie-hellman-group1-sha1',
    ],
    cipher: [
      'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
      'aes128-cbc', 'aes256-cbc', '3des-cbc',
    ],
    serverHostKey: ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-dss'],
    hmac: ['hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'],
  }
});
