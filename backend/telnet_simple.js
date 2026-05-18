const net = require('net');

const HOST = '172.16.16.2';
const PORT = 23;
const USERNAME = 'admin';
const PASSWORD = 'ruijie@123';

const socket = new net.Socket();
let data = '';
let step = 0;
let timer = null;

function send(text) {
  process.stdout.write(`[SEND] ${JSON.stringify(text)}\n`);
  socket.write(text);
}

socket.connect(PORT, HOST, () => {
  process.stdout.write(`[CONNECTED] ${HOST}:${PORT}\n`);
});

socket.on('data', (chunk) => {
  const text = chunk.toString('utf8');
  data += text;
  process.stdout.write(text);

  if (timer) clearTimeout(timer);
  timer = setTimeout(doStep, 500);
});

socket.on('error', (e) => {
  process.stdout.write(`[ERR] ${e.message}\n`);
});

socket.on('close', () => {
  process.stdout.write('[CLOSE]\n');
  console.log('\n=== RESULT ===\n' + data.substring(0, 3000));
  process.exit(0);
});

function doStep() {
  if (step === 0 && (data.includes('sername') || data.includes('ogin'))) {
    step = 1;
    send(USERNAME + '\r\n');
    return;
  }
  if (step === 1 && data.includes('assword')) {
    step = 2;
    send(PASSWORD + '\r\n');
    return;
  }
  if (step === 2 && (data.includes('#') || data.includes('>'))) {
    step = 3;
    send('show version\r\n');
    timer = setTimeout(() => {
      send('show lldp neighbor\r\n');
      timer = setTimeout(() => {
        send('exit\r\n');
      }, 5000);
    }, 4000);
    return;
  }
  // Timeout fallback
  if (step < 3) {
    timer = setTimeout(() => {
      console.log('\n[TIMEOUT at step ' + step + ']');
      socket.end();
    }, 8000);
  }
}

// Initial timeout
timer = setTimeout(() => {
  console.log('\n=== TOTAL TIMEOUT ===\n' + data.substring(0, 3000));
  socket.end();
}, 35000);
