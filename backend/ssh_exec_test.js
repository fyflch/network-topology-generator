const { Client } = require('ssh2');

const c = new Client();
c.on('ready', () => {
  console.log('SSH ready, trying exec...');
  c.exec('show version', (err, stream) => {
    if (err) { console.log('exec error:', err.message); c.end(); process.exit(1); }
    let out = '';
    stream.on('data', d => { out += d.toString(); });
    stream.on('close', () => {
      console.log('SUCCESS! Output:\n' + out.substring(0, 800));
      c.end();
      process.exit(0);
    });
    stream.stderr.on('data', d => console.log('stderr:', d.toString()));
  });
});
c.on('error', e => { console.log('ERR:', e.message); process.exit(1); });

c.connect({
  host: '172.16.16.2', port: 22,
  username: 'admin', password: 'ruijie@123',
  readyTimeout: 20000,
  tryKeyboard: false,
  algorithms: {
    kex: ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
    cipher: ['aes128-cbc', 'aes256-cbc', '3des-cbc'],
    serverHostKey: ['ssh-rsa', 'ssh-dss'],
  }
});
