const snmp = require('net-snmp');
const ips = ['172.16.16.2','172.16.16.7','172.16.16.51','172.16.16.52'];
ips.forEach(ip => {
  const s = snmp.createSession(ip, 'public', {timeout:5000,retries:1,version:snmp.Version2c});
  s.get(['1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.1.1.0'], (e, vbs) => {
    if (e) {
      console.log(ip + ' ERR:' + e.message);
    } else {
      const n = Buffer.isBuffer(vbs[0].value) ? vbs[0].value.toString('utf8').trim() : String(vbs[0].value);
      const d = Buffer.isBuffer(vbs[1].value) ? vbs[1].value.toString('utf8').trim() : String(vbs[1].value);
      console.log(ip + ' NAME:' + n + ' | DESC:' + d.substring(0,60));
    }
    s.close();
  });
});
