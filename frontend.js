require('http').createServer((req, res) => {
  const path = require('path');
  const fs = require('fs');
  const url = req.url.split('?')[0];
  const filePath = path.join(__dirname, url === '/' || url === '' ? 'index.html' : url);
  
  try {
    const content = fs.readFileSync(filePath);
    const ext = path.extname(filePath);
    const mimeTypes = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };
    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain', 'Access-Control-Allow-Origin': '*' });
    res.end(content);
  } catch(e) {
    res.writeHead(404);
    res.end('Not found: ' + url);
  }
}).listen(8899, () => {
  console.log('Frontend server running on http://localhost:8899');
});
