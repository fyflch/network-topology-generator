const net = require('net');
const fs = require('fs');

const HOST = '172.16.16.2';
const PORT = 23;
const USERNAME = 'admin';
const PASSWORD = 'ruijie@123';

let data = '';
let step = 0;
let timer = null;

const socket = new net.Socket();

socket.connect(PORT, HOST, () => {
  fs.appendFileSync('telnet_result.txt', `[CONNECTED] ${HOST}:${PORT}\n`);
});

socket.on('data', (chunk) => {
  const text = chunk.toString('utf8');
  data += text;
  fs.appendFileSync('telnet_result.txt', text);
  if (timer) clearTimeout(timer);
  timer = setTimeout(doStep, 500);
});

socket.on('error', (e) => {
  fs.appendFileSync('telnet_result.txt', `[ERR] ${e.message}\n`);
});

socket.on('close', () => {
  fs.appendFileSync('telnet_result.txt', `\n[CLOSED at step ${step}]\n=== ALL DATA ===\n${data}\n`);
  process.exit(0);
});

function send(text) { socket.write(text); fs.appendFileSync('telnet_result.txt', `[SEND] ${JSON.stringify(text)}\n`); }

function doStep() {
  if (step === 0 && /[Uu]sername|[Ll]ogin/.test(data)) { step = 1; send(USERNAME + '\r\n'); return; }
  if (step === 1 && /[Pp]assword/.test(data)) { step = 2; send(PASSWORD + '\r\n'); return; }
  if (step === 2 && /[#>]/.test(data)) {
    step = 3; fs.appendFileSync('telnet_result.txt', '[LOGGED IN!]\n');
    send('show version\r\n');
    timer = setTimeout(() => { send('show lldp neighbor\r\n'); }, 5000);
    timer = setTimeout(() => { send('exit\r\n'); }, 12000);
    return;
  }
  timer = setTimeout(() => { fs.appendFileSync('telnet_result.txt', `[TIMEOUT step ${step}]\n`); socket.end(); }, 10000);
}

timer = setTimeout(() => { fs.appendFileSync('telnet_result.txt', '[TOTAL TIMEOUT]\n'); socket.end(); }, 25000);
