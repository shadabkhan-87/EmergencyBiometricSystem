// server/index.js
const express = require('express');
const http = require('http');
const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { spawn } = require('child_process');
const WebSocket = require('ws');

const app = express();
const PORT = 3000;

// Load users metadata file (5 sample users)
const USERS_FILE = path.join(__dirname, 'users.json');
let users = require(USERS_FILE);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// simple endpoint to fetch user metadata
app.get('/api/user/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const u = users.find(x => x.id === id);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

// image upload
const upload = multer({ dest: path.join(__dirname, 'uploads/') });
app.post('/api/user/:id/photo', upload.single('photo'), (req, res) => {
  const id = parseInt(req.params.id);
  const u = users.find(x => x.id === id);
  if (!u) return res.status(404).json({ error: 'not found' });
  const ext = path.extname(req.file.originalname) || '.jpg';
  const newName = `user_${id}${ext}`;
  const newPath = path.join(__dirname, 'uploads', newName);
  fs.renameSync(req.file.path, newPath);
  u.photo = '/uploads/' + newName;
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  res.json({ ok: true, photo: u.photo });
});

// create http server so we can attach WebSocket server to it
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// broadcast helper
function broadcastJSON(obj) {
  const s = JSON.stringify(obj);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) client.send(s);
  });
}

// === Serial port setup (modern serialport API) ===
// Usage: node index.js COM5
const SERIAL_PATH = process.argv[2] || '/dev/ttyACM0';
const serial = new SerialPort({ path: SERIAL_PATH, baudRate: 57600, autoOpen: false });
const parser = serial.pipe(new ReadlineParser({ delimiter: '\r\n' }));

serial.open(err => {
  if (err) {
    console.error('Error opening serial:', err.message);
    return;
  }
  console.log('Serial open on', SERIAL_PATH);
  broadcastJSON({ type: 'serial', message: 'open', port: SERIAL_PATH });
});

parser.on('data', line => {
  if (!line) return;
  console.log('SERIAL:', line);

  if (line.startsWith('MATCHED:')) {
    const id = parseInt(line.split(':')[1]);
    if (!Number.isNaN(id)) {
      console.log('Matched user', id);
      // broadcast to websocket clients
      broadcastJSON({ type: 'matched', id });
    }
  } else if (line.startsWith('ENROLLED:')) {
    const id = line.split(':')[1];
    console.log('Enrolled user', id);
    broadcastJSON({ type: 'enrolled', id });
  } else if (line.startsWith('DELETED:')) {
    const id = line.split(':')[1];
    console.log('Deleted user', id);
    broadcastJSON({ type: 'deleted', id });
  } else if (line.startsWith('ENROLL_FAIL:')) {
    const id = line.split(':')[1];
    console.log('Enroll failed for', id);
    broadcastJSON({ type: 'enroll_fail', id });
  } else if (line.startsWith('DELETE_FAIL:')) {
    const id = line.split(':')[1];
    console.log('Delete failed for', id);
    broadcastJSON({ type: 'delete_fail', id });
  } else {
    // other serial lines
    broadcastJSON({ type: 'log', message: line });
  }
});

wss.on('connection', (ws, req) => {
  console.log('WS client connected');
  ws.send(JSON.stringify({ type: 'welcome', message: 'connected' }));
});

// helper: open URL in default browser (Windows/Mac/Linux)
function openUrl(url) {
  const plat = process.platform;
  let cmd, args;
  if (plat === 'win32') {
    cmd = 'cmd';
    args = ['/c', 'start', '""', url];
  } else if (plat === 'darwin') {
    cmd = 'open';
    args = [url];
  } else {
    cmd = 'xdg-open';
    args = [url];
  }
  const child = spawn(cmd, args, { detached: true, stdio: 'ignore' });
  child.unref();
}

// Optionally auto-open user page on MATCHED — also broadcast to WS so pages can react.
// If you prefer NOT to auto-open, comment the openUrl call below inside the parser 'MATCHED' handler above.
// (left out of automatic call here; pages will react via WS)
//
// Example: to auto-open when matched, uncomment:
// openUrl(`http://localhost:${PORT}/user.html?id=${encodeURIComponent(id)}`);

server.listen(PORT, () => console.log(`Server + WebSocket running on http://localhost:${PORT}`));
