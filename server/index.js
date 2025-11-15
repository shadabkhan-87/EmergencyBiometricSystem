// server/index.js
// Full server: serial + websocket + persistent sessions (node-persist) + session expiry cleanup
// Multi-admin support with username/password authentication from admin.json

const express = require('express');
const http = require('http');
const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const storage = require('node-persist');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
const ADMINS_FILE = path.join(__dirname, 'admin.json');

// Session settings
const SESSION_COOKIE = 'fp_admin_sess';
const SESSION_TTL_DAYS = process.env.SESSION_TTL_DAYS ? parseInt(process.env.SESSION_TTL_DAYS) : 7; // default 7 days
const SESSION_CLEANUP_INTERVAL_MIN = 60; // cleanup every hour

// multer for uploads
const upload = multer({ dest: path.join(__dirname, 'uploads/') });

// ========== ADMIN.JSON HELPERS ==========

/**
 * Reads admin.json and returns the array of admins
 * Creates file with empty array if it doesn't exist
 */
function readAdmins() {
  try {
    if (!fs.existsSync(ADMINS_FILE)) {
      fs.writeFileSync(ADMINS_FILE, JSON.stringify([], null, 2));
      return [];
    }
    const data = fs.readFileSync(ADMINS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    console.error('Error reading admin.json:', e);
    return [];
  }
}

/**
 * Writes the admins array to admin.json
 */
function writeAdmins(admins) {
  try {
    fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 2));
    return true;
  } catch (e) {
    console.error('Error writing admin.json:', e);
    return false;
  }
}

/**
 * Finds an admin by username
 */
function findAdminByUsername(username) {
  const admins = readAdmins();
  return admins.find(admin => admin.username === username);
}

/**
 * Adds a new admin to admin.json
 */
function addAdmin(adminData) {
  const admins = readAdmins();
  admins.push(adminData);
  return writeAdmins(admins);
}

// ========== SESSION STORAGE ==========

async function initSessionStorage() {
  await storage.init({
    dir: path.join(__dirname, 'session_store'),
    stringify: JSON.stringify,
    parse: JSON.parse,
    encoding: 'utf8'
  });
  // run cleanup once at startup
  await cleanupExpiredSessions();
  // set periodic cleanup
  setInterval(cleanupExpiredSessions, SESSION_CLEANUP_INTERVAL_MIN * 60 * 1000);
}

async function createSession(username) {
  const token = crypto.randomBytes(18).toString('hex');
  const now = Date.now();
  await storage.setItem(token, { createdAt: now, username });
  return token;
}

async function sessionExists(token) {
  if (!token) return false;
  try {
    const s = await storage.getItem(token);
    if (!s || !s.createdAt) return false;
    // check TTL
    const ageMs = Date.now() - s.createdAt;
    const ttlMs = SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;
    if (ageMs > ttlMs) {
      await storage.removeItem(token);
      return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

async function cleanupExpiredSessions() {
  try {
    const keys = await storage.keys();
    const now = Date.now();
    const ttlMs = SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;
    let removed = 0;
    for (const k of keys) {
      const s = await storage.getItem(k);
      if (!s || !s.createdAt) {
        await storage.removeItem(k);
        removed++;
        continue;
      }
      if (now - s.createdAt > ttlMs) {
        await storage.removeItem(k);
        removed++;
      }
    }
    if (removed > 0) console.log(`Session cleanup removed ${removed} expired sessions`);
  } catch (e) {
    console.error('Session cleanup failed', e);
  }
}

// ========== AUTH MIDDLEWARE ==========

/**
 * Middleware to require authentication
 */
async function requireAuthAsync(req, res, next) {
  try {
    const token = req.cookies ? req.cookies[SESSION_COOKIE] : null;
    const ok = await sessionExists(token);
    if (!ok) return res.status(401).json({ error: 'unauthorized' });
    return next();
  } catch (e) {
    return res.status(500).json({ error: 'server error' });
  }
}

// ========== USER DATA ==========

// load users from file
function loadUsers() {
  delete require.cache[require.resolve(USERS_FILE)];
  return require(USERS_FILE);
}
let users = loadUsers();

// ========== EXPRESS MIDDLEWARE ==========

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ========== AUTH ENDPOINTS ==========

/**
 * POST /api/postapi
 * Login with username and password
 */
app.post('/api/postapi', async (req, res) => {
  console.log(req);
  const { username, password } = req.body || {};

  // Validate input
  if (!username || !password) {
    return res.status(400).json({
      ok: false,
      message: 'Username and password are required'
    });
  }

  // Find admin by username
  const admin = findAdminByUsername(username);

  if (!admin) {
    return res.status(404).json({
      ok: false,
      message: 'Admin not found'
    });
  }

  // Check password
  if (admin.password !== password) {
    return res.status(401).json({
      ok: false,
      message: 'Invalid password'
    });
  }

  // Create session
  try {
    const token = await createSession(username);
    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: SESSION_TTL_DAYS * 24 * 60 * 60 * 1000
    });
    return res.json({
      ok: true,
      message: 'Login successful',
      admin: {
        username: admin.username,
        firstName: admin.firstName,
        lastName: admin.lastName,
        email: admin.email
      }
    });
  } catch (e) {
    console.error('Session creation error:', e);
    return res.status(500).json({
      ok: false,
      message: 'Server error'
    });
  }
});

/**
 * POST /api/signup
 * Create a new admin account
 */
app.post('/api/signup', async (req, res) => {
  console.log(req);
  const { firstName, lastName, phone, email, username, password } = req.body || {};

  // Validate all required fields
  if (!firstName || !lastName || !phone || !email || !username || !password) {
    return res.status(400).json({
      ok: false,
      message: 'All fields are required'
    });
  }

  // Check if username already exists
  const existingAdmin = findAdminByUsername(username);
  if (existingAdmin) {
    return res.status(409).json({
      ok: false,
      message: 'Username already exists'
    });
  }

  // Create new admin object
  const newAdmin = {
    id: Date.now(), // Simple ID generation
    firstName: firstName.trim(),
    lastName: lastName.trim(),
    phone: phone.trim(),
    email: email.trim(),
    username: username.trim(),
    password: password, // In production, hash this!
    createdAt: new Date().toISOString()
  };

  // Save to admin.json
  const success = addAdmin(newAdmin);

  if (success) {
    console.log(`New admin created: ${username}`);
    return res.json({
      ok: true,
      message: 'Admin created successfully'
    });
  } else {
    return res.status(500).json({
      ok: false,
      message: 'Failed to create admin'
    });
  }
});

/**
 * POST /api/logout
 * Logout and destroy session
 */
app.post('/api/logout', async (req, res) => {
  try {
    const token = req.cookies ? req.cookies[SESSION_COOKIE] : null;
    if (token) await storage.removeItem(token);
    res.clearCookie(SESSION_COOKIE);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false });
  }
});

/**
 * GET /api/admin/status
 * Check if current session is valid
 */
app.get('/api/admin/status', async (req, res) => {
  const token = req.cookies ? req.cookies[SESSION_COOKIE] : null;
  const ok = await sessionExists(token);
  res.json({ ok });
});

// ========== PUBLIC API ==========

/**
 * GET /api/user/:id
 * Get user information by ID (public)
 */
app.get('/api/user/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const u = users.find(x => x.id === id);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

// ========== PROTECTED API ==========

/**
 * PUT /api/user/:id
 * Update user information (protected)
 */
app.put('/api/user/:id', requireAuthAsync, (req, res) => {
  const id = parseInt(req.params.id);
  const idx = users.findIndex(x => x.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not found' });
  
  const allowed = ['name', 'nationality', 'medical', 'emergency'];
  const payload = req.body || {};
  
  for (const k of allowed) {
    if (k in payload) users[idx][k] = String(payload[k]);
  }
  
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  users = loadUsers();
  res.json({ ok: true, user: users[idx] });
});

/**
 * POST /api/user/:id/photo
 * Upload user photo (public, change to requireAuthAsync if needed)
 */
app.post('/api/user/:id/photo', upload.single('photo'), (req, res) => {
  const id = parseInt(req.params.id);
  const idx = users.findIndex(x => x.id === id);
  
  if (idx === -1) {
    if (req.file && req.file.path) fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'not found' });
  }
  
  const ext = path.extname(req.file.originalname) || '.jpg';
  const newName = `user_${id}${ext}`;
  const newPath = path.join(__dirname, 'uploads', newName);
  
  fs.renameSync(req.file.path, newPath);
  users[idx].photo = '/uploads/' + newName;
  
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  users = loadUsers();
  
  res.json({ ok: true, photo: users[idx].photo, user: users[idx] });
});

// ========== WEBSOCKET BROADCASTING ==========

function broadcastJSON(obj) {
  const s = JSON.stringify(obj);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) client.send(s);
  });
}

// ========== SERIAL PORT SETUP ==========

const SERIAL_PATH = process.argv[2] || process.env.SERIAL_PORT || '/dev/ttyACM0';
const serial = new SerialPort({ path: SERIAL_PATH, baudRate: 57600, autoOpen: false });
const parser = serial.pipe(new ReadlineParser({ delimiter: '\r\n' }));

serial.open(err => {
  if (err) {
    console.error('Error opening serial:', err.message);
    broadcastJSON({ type: 'serial', state: 'error', message: err.message });
    return;
  }
  console.log('Serial open on', SERIAL_PATH);
  broadcastJSON({ type: 'serial', state: 'open', port: SERIAL_PATH });
});

parser.on('data', line => {
  if (!line) return;
  console.log('SERIAL:', line);
  broadcastJSON({ type: 'log', message: line });

  if (line.startsWith('MATCHED:')) {
    const id = parseInt(line.split(':')[1]);
    if (!Number.isNaN(id)) {
      console.log('Matched user', id);
      broadcastJSON({ type: 'matched', id });
      
      // Auto-open user page for every match
      const baseUrl = `http://localhost:${PORT}/user.html?id=${encodeURIComponent(id)}`;
      const sep = baseUrl.includes('?') ? '&' : '?';
      const urlWithStamp = `${baseUrl}${sep}t=${Date.now()}`;
      try {
        openUrl(urlWithStamp);
      } catch (e) {
        console.error('Failed to open browser:', e);
      }
    }
  } else if (line.startsWith('ENROLLED:')) {
    const id = line.split(':')[1];
    broadcastJSON({ type: 'enrolled', id });
  } else if (line.startsWith('DELETED:')) {
    const id = line.split(':')[1];
    broadcastJSON({ type: 'deleted', id });
  } else if (line.startsWith('ENROLL_FAIL:')) {
    const id = line.split(':')[1];
    broadcastJSON({ type: 'enroll_fail', id });
  } else if (line.startsWith('DELETE_FAIL:')) {
    const id = line.split(':')[1];
    broadcastJSON({ type: 'delete_fail', id });
  }
});

// ========== WEBSOCKET HANDLING ==========

let nextClientId = 1;
const clients = new Map();

wss.on('connection', (ws) => {
  const clientId = nextClientId++;
  clients.set(clientId, ws);
  ws.send(JSON.stringify({ type: 'welcome', clientId }));
  broadcastJSON({ type: 'clients', clients: Array.from(clients.keys()) });

  ws.on('message', (m) => {
    try {
      const msg = JSON.parse(m.toString());
      if (msg && msg.type === 'open' && msg.id) {
        const url = `http://localhost:${PORT}/user.html?id=${encodeURIComponent(msg.id)}`;
        try {
          openUrl(url);
          ws.send(JSON.stringify({ type: 'opened', id: msg.id }));
        } catch (e) {
          ws.send(JSON.stringify({ type: 'error', message: String(e) }));
        }
      }
    } catch (e) {
      // ignore invalid messages
    }
  });

  ws.on('close', () => {
    clients.delete(clientId);
    broadcastJSON({ type: 'clients', clients: Array.from(clients.keys()) });
  });
});

// ========== HELPER TO OPEN BROWSER ==========

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

// ========== START SERVER ==========

initSessionStorage().then(() => {
  server.listen(PORT, () => {
    console.log(`Server + WebSocket running on http://localhost:${PORT}`);
    console.log(`Admin file: ${ADMINS_FILE}`);
    
    // Create admin.json if it doesn't exist
    if (!fs.existsSync(ADMINS_FILE)) {
      console.log('Creating admin.json with empty array');
      writeAdmins([]);
    }
  });
}).catch(err => {
  console.error('Failed to initialize session storage:', err);
  process.exit(1);
});