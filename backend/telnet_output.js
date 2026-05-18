const net = require('net');
const fs = require('fs');

const HOST = '172.16.16.2';
const PORT = 23;
const USERNAME = 'admin';
const PASSWORD = 'ruijie@123';

const log = [];
function logIt(msg) { log.push(msg); console.log(msg); }

const socket = new net.Socket();
let data = '';
let step = 0;
let timer = null;

socket.connect(PORT, HOST, () => { logIt(`[CONNECTED] ${HOST}:${PORT}`); });

socket.on('data', (chunk) => {
  const text = chunk.toString('utf8');
  data += text;
  process.stdout.write(text);
  if (timer) clearTimeout(timer);
  timer = setTimeout(doStep, 500);
});

socket.on('error', (e) => { logIt(`[ERR] ${e.message}`); });

socket.on('close', () => {
  logIt('[CLOSE]');
  const result = '\n=== FINAL ===\n' + data;
  fs.writeFileSync('c:/Users/Administrator/WorkBuddy/20260513095907/app/backend/telnet_result.txt', result);
  logIt('[SAVED] telnet_result.txt');
  process.exit(0);
});

function send(text) { socket.write(text); logIt(`[SEND] ${JSON.stringify(text)}`); }

function doStep() {
  if (step === 0 && /[Uu]sername|ogin/.test(data)) { step = 1; send(USERNAME + '\r\n'); return; }
  if (step === 1 && /[Pp]assword/.test(data)) { step = 2; send(PASSWORD + '\r\n'); return; }
  if (step === 2 && /[#>]/.test(data)) {
    step = 3; send('show version\r\n');
    timer = setTimeout(() => { send('show lldp neighbor\r\n'); }, 4000);
    timer = setTimeout(() => { send('exit\r\n'); }, 10000);
    return;
  }
  timer = setTimeout(() => { logIt('[STEP ' + step + ' TIMEOUT]'); socket.end(); }, 15000);
}

timer = setTimeout(() => { logIt('[TOTAL TIMEOUT]'); socket.end(); }, 30000);
