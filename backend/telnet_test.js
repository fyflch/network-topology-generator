/**
 * Telnet 交互式测试：登录锐捷 RGOS 设备
 */
const net = require('net');

const HOST = '172.16.16.2';
const PORT = 23;
const USERNAME = 'admin';
const PASSWORD = 'ruijie@123';
const TIMEOUT = 20000;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function telnetCmd(command) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('Telnet timeout'));
    }, TIMEOUT);

    let data = '';
    let loginPhase = 0; // 0=waiting for user prompt, 1=waiting for pass prompt, 2=waiting for command result
    let userPrompt = /[Uu]sername:|$/;
    let passPrompt = /[Pp]assword:|$/;
    let loginDone = false;

    socket.connect(PORT, HOST, () => {
      console.log(`[${HOST}:${PORT}] Connected`);
    });

    socket.on('data', async (chunk) => {
      const text = chunk.toString('utf8');
      data += text;
      console.log('[RCV]', JSON.stringify(text));
      clearTimeout(timer);

      if (!loginDone) {
        if (text.includes('Username') || text.includes('username') || text.includes('login')) {
          console.log('[SEND] username');
          socket.write(USERNAME + '\r\n');
          await sleep(500);
        } else if (text.includes('Password') || text.includes('password')) {
          console.log('[SEND] password');
          socket.write(PASSWORD + '\r\n');
          await sleep(1500);
          // Check if logged in
          if (data.includes('#') || data.includes('>')) {
            loginDone = true;
            console.log('[LOGGED IN] Sending command:', command);
            socket.write(command + '\r\n');
            await sleep(3000);
            console.log('[SEND] exit');
            socket.write('exit\r\n');
            setTimeout(() => {
              clearTimeout(timer);
              console.log('\n=== FINAL OUTPUT ===\n' + data);
              socket.end();
              resolve(data);
            }, 1000);
          }
        }
      }

      // Reset timer
      timer = setTimeout(() => {
        console.log('\n=== OUTPUT ===\n' + data);
        socket.end();
        resolve(data);
      }, 5000);
    });

    socket.on('error', e => {
      clearTimeout(timer);
      console.log('[ERR]', e.message);
      reject(e);
    });

    socket.on('close', () => {
      clearTimeout(timer);
      console.log('[CLOSE]');
    });
  });
}

// 简单交互式
const socket = new net.Socket();
let data = '';
let step = 0;

socket.setTimeout(TIMEOUT);
socket.connect(PORT, HOST, () => {
  console.log('Connected to', HOST, PORT);
});

socket.on('data', (chunk) => {
  data += chunk.toString();
  process.stdout.write(chunk.toString());

  // Step 0: wait for username prompt
  if (step === 0 && (data.includes('Username') || data.includes('username') || data.includes('ogin'))) {
    step = 1;
    console.log('\n--- Sending username ---');
    socket.write(USERNAME + '\r\n');
  }
  // Step 1: wait for password prompt
  else if (step === 1 && data.includes('Password')) {
    step = 2;
    console.log('--- Sending password ---');
    socket.write(PASSWORD + '\r\n');
  }
  // Step 2: wait for prompt after login
  else if (step === 2 && (data.includes('#') || data.includes('>'))) {
    step = 3;
    console.log('--- Logged in! Sending show version ---');
    socket.write('show version\r\n');
    setTimeout(() => {
      console.log('--- Sending show lldp neighbor ---');
      socket.write('show lldp neighbor\r\n');
      setTimeout(() => {
        console.log('--- Exiting ---');
        socket.write('exit\r\n');
        setTimeout(() => {
          socket.end();
          console.log('\n\n=== ALL DONE ===');
          process.exit(0);
        }, 1000);
      }, 5000);
    }, 3000);
  }
});

socket.on('timeout', () => {
  console.log('TIMEOUT');
  socket.end();
  process.exit(1);
});

socket.on('error', (e) => {
  console.log('ERR:', e.message);
  process.exit(1);
});

socket.on('close', () => {
  console.log('Connection closed');
});
