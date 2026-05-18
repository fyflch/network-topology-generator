const net = require('net');
const fs = require('fs');
const HOST = '172.16.16.2';
const PORT = 23;
const socket = new net.Socket();
let data = '';
let step = 0;

socket.connect(PORT, HOST, () => { process.stdout.write('[CONNECTED]\n'); });
socket.on('data', (chunk) => {
  const text = chunk.toString();
  data += text;
  process.stdout.write(text);
  if (step === 0 && /[Uu]sername/.test(data)) { step = 1; socket.write('admin\r\n'); process.stdout.write('[SEND admin]\n'); }
  else if (step === 1 && /[Pp]assword/.test(data)) { step = 2; socket.write('ruijie@123\r\n'); process.stdout.write('[SEND pass]\n'); }
  else if (step === 2 && /[#>]/.test(data)) {
    step = 3; socket.write('show version\r\n'); process.stdout.write('[SEND show version]\n');
    setTimeout(() => { socket.write('show lldp neighbor\r\n'); process.stdout.write('[SEND show lldp]\n'); }, 3000);
    setTimeout(() => { socket.write('exit\r\n'); process.stdout.write('[EXIT]\n'); }, 8000);
    setTimeout(() => { fs.appendFileSync('c:/Users/Administrator/WorkBuddy/20260513095907/app/backend/telnet_result.txt', data); socket.end(); process.exit(0); }, 11000);
  }
});
socket.on('error', (e) => { process.stdout.write('[ERR ' + e.message + ']\n'); });
socket.on('close', () => { process.stdout.write('[CLOSE]\n'); });
setTimeout(() => { fs.appendFileSync('c:/Users/Administrator/WorkBuddy/20260513095907/app/backend/telnet_result.txt', data); process.exit(0); }, 20000);
