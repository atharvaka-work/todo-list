// DELIBERATELY VULNERABLE CODE - Semgrep test bed. Never import or deploy this file.
// Each case is tagged [Sxx] so scan results can be mapped back to it.
import express from 'express';
import { exec, spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import http from 'http';
import jwt from 'jsonwebtoken';
import mysql from 'mysql';
import yaml from 'js-yaml';
import _ from 'lodash';

const app = express();
app.use(express.json());
const db = mysql.createConnection({ host: 'localhost' });

// [S01] Hardcoded credentials (fake values)
const DB_PASSWORD = 'SuperS3cretPassw0rd!';
const apiKey = 'fake-live-key-51Hf4keKeyThatLooksReal00';
const SOCKET_TOKEN = 'sktsec_FAKEfakeFAKEfakeFAKEfake1234567890';
const JWT_SECRET = 'my-hardcoded-jwt-secret';

// [S02] Command injection via exec with user input
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

// [S03] Command injection via shell: true
app.get('/grep', (req, res) => {
  spawn('grep', [req.query.term, 'log.txt'], { shell: true });
  res.end();
});

// [S04] SQL injection (string concatenation)
app.get('/user', (req, res) => {
  db.query("SELECT * FROM users WHERE id = '" + req.query.id + "'", (e, rows) => res.json(rows));
});

// [S05] SQL injection (template literal)
app.get('/search', (req, res) => {
  db.query(`SELECT * FROM items WHERE name LIKE '%${req.query.q}%'`, (e, rows) => res.json(rows));
});

// [S06] Path traversal
app.get('/file', (req, res) => {
  res.sendFile(path.join(__dirname, 'uploads', req.query.name));
});

// [S07] Path traversal via fs.readFile
app.get('/read', (req, res) => {
  fs.readFile('./data/' + req.params.file, 'utf8', (e, d) => res.send(d));
});

// [S08] Code injection: eval of request data
app.post('/calc', (req, res) => {
  res.send(String(eval(req.body.expression)));
});

// [S09] Code injection: new Function
app.post('/run', (req, res) => {
  const fn = new Function('x', req.body.code);
  res.send(String(fn(1)));
});

// [S10] Reflected XSS: user input written straight into HTML
app.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

// [S11] Open redirect
app.get('/go', (req, res) => {
  res.redirect(req.query.url);
});

// [S12] SSRF: server fetches any URL the user gives
app.get('/proxy', (req, res) => {
  http.get(req.query.target, (r) => r.pipe(res));
});

// [S13] Weak hashing for passwords
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

// [S14] Insecure randomness for a security token
function makeResetToken() {
  return Math.random().toString(36).slice(2);
}

// [S15] JWT signed with hardcoded secret / verified with 'none' allowed
function issueToken(user) {
  return jwt.sign({ id: user.id }, 'hardcoded-secret-123');
}
function checkToken(t) {
  return jwt.verify(t, JWT_SECRET, { algorithms: ['none', 'HS256'] });
}

// [S16] Information leak: stack trace and env sent to the client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack, env: process.env });
});

// [S17] Information leak: logging secrets
function login(user, password) {
  console.log('Login attempt', user, 'password=', password, 'db=', DB_PASSWORD);
}

// [S18] Unsafe YAML load (js-yaml 3.x load can construct functions)
app.post('/config', (req, res) => {
  res.json(yaml.load(req.body.yaml));
});

// [S19] Prototype pollution via deep merge of user input
app.post('/settings', (req, res) => {
  const settings = {};
  _.merge(settings, req.body);
  res.json(settings);
});

// [S20] Prototype pollution via bracket assignment
app.post('/set', (req, res) => {
  const obj = {};
  obj[req.body.key][req.body.sub] = req.body.value;
  res.json(obj);
});

// [S21] ReDoS: catastrophic backtracking regex on user input
app.get('/validate', (req, res) => {
  const re = new RegExp('^(a+)+$');
  res.send(String(re.test(req.query.input)));
});

// [S22] Regex built from user input (ReDoS / injection)
app.get('/match', (req, res) => {
  res.send(String(new RegExp(req.query.pattern).test('abc')));
});

// [S23] Insecure cookie (no httpOnly / secure)
app.get('/session', (req, res) => {
  res.cookie('session', makeResetToken(), { httpOnly: false, secure: false });
  res.end();
});

// [S24] Disabled TLS certificate verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// [S25] Timing-unsafe comparison of secrets
function checkApiKey(given) {
  return given === apiKey;
}

// [S26] Weak cipher with static IV
function encrypt(text) {
  const cipher = crypto.createCipheriv('des-ecb', Buffer.from('12345678'), null);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

// [S27] Mass assignment: whole request body saved to DB
app.post('/profile', (req, res) => {
  db.query('UPDATE users SET ?', req.body);
  res.end();
});

// [S28] Missing auth: admin route with no check
app.delete('/admin/users/:id', (req, res) => {
  db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.end();
});

// [S29] Server listens on all interfaces, no helmet / rate limiting
app.listen(3000, '0.0.0.0');

export { hashPassword, issueToken, checkToken, login, checkApiKey, encrypt, SOCKET_TOKEN };
