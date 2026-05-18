const { Client } = require('ssh2');

const c = new Client();
const t = setTimeout(() => { console.log('TIMEOUT'); c.end(); process.exit(1); }, 30000);

c.on('ready', () => {
  console.log('SSH connected, opening shell...');
  c.shell((err, stream) => {
    if (err) { console.log('shell error:', err.message); c.end(); process.exit(1); }

    let out = '';
    stream.on('data', d => { out += d.toString(); });
    stream.on('close', () => {
      console.log('SHELL CLOSED\n--- OUTPUT ---\n' + out);
      c.end();
      process.exit(0);
    });

    // 发送命令，延迟执行确保 shell 就绪
    setTimeout(() => {
      console.log('Sending: show version');
      stream.write('show version\n');
      setTimeout(() => {
        console.log('Sending: show lldp neighbor');
        stream.write('show lldp neighbor\n');
        setTimeout(() => {
          console.log('Sending exit');
          stream.write('exit\n');
          setTimeout(() => { stream.end(); }, 3000);
        }, 5000);
      }, 3000);
    }, 3000);
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
