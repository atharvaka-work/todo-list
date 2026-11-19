// Test cases for node-security.yml. Run with: semgrep --test .semgrep/rules
// "ruleid" marks a line that must match; "ok" marks a line that must not.
// All secrets here are fake.
import express from 'express';
import { exec, execFile } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import http from 'http';
import jwt from 'jsonwebtoken';
import yaml from 'js-yaml';
import _ from 'lodash';

const app = express();
const db = {};

app.get('/sql', (req, res) => {
  // ruleid: express-sql-injection
  db.query("SELECT * FROM users WHERE id = '" + req.query.id + "'");
  // ruleid: express-sql-injection
  db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);
  const sql = 'DELETE FROM t WHERE id = ' + req.params.id;
  // ruleid: express-sql-injection
  db.execute(sql);
  // ok: express-sql-injection
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);
  // ok: express-sql-injection
  db.query('SELECT 1');
});

app.get('/cmd', (req, res) => {
  // ruleid: express-command-injection
  exec('ping -c 1 ' + req.query.host);
  const cmd = `nslookup ${req.body.domain}`;
  // ruleid: express-command-injection
  exec(cmd, () => {});
  // ok: express-command-injection
  execFile('ping', ['-c', '1', req.query.host]);
  // ok: express-command-injection
  /^[a-z]+$/.exec(req.query.host);
  // ok: express-command-injection
  exec('git status');
});

app.get('/fs', (req, res) => {
  // ruleid: express-fs-path-traversal
  fs.readFile('./data/' + req.params.file, () => {});
  // ruleid: express-fs-path-traversal
  fs.unlinkSync(path.join('/uploads', req.query.name));
  // ok: express-fs-path-traversal
  fs.readFile(path.join('/uploads', path.basename(req.query.name)), () => {});
  // ok: express-fs-path-traversal
  fs.readFileSync('./config.json');
});

app.get('/ssrf', async (req, res) => {
  // ruleid: express-ssrf
  http.get(req.query.target, (r) => r.pipe(res));
  const url = 'http://' + req.query.host + '/status';
  // ruleid: express-ssrf
  await fetch(url);
  // ok: express-ssrf
  await fetch('https://api.example.com/status', { headers: { 'x-id': req.query.id } });
});

app.post('/merge', (req, res) => {
  const settings = {};
  // ruleid: express-prototype-pollution
  _.merge(settings, req.body);
  const obj = {};
  // ruleid: express-prototype-pollution
  obj[req.body.key][req.body.sub] = req.body.value;
  // ok: express-prototype-pollution
  _.merge(settings, { theme: 'dark' });
  // ok: express-prototype-pollution
  obj.a.b = req.body.value;
});

export function yamlCases(text) {
  // ruleid: js-yaml-unsafe-load
  const a = yaml.load(text);
  // ok: js-yaml-unsafe-load
  const b = yaml.load(text, { schema: yaml.JSON_SCHEMA });
  // ok: js-yaml-unsafe-load
  const c = yaml.safeLoad(text);
  return [a, b, c];
}

app.use((err, req, res, next) => {
  // ruleid: express-error-details-in-response
  res.status(500).json({ error: err.stack });
  // ruleid: express-error-details-in-response
  res.send(process.env);
  // ok: express-error-details-in-response
  res.status(500).json({ error: 'Internal error' });
  // ok: express-error-details-in-response
  console.error(err.stack);
});

export function logCases(user, password, apiToken, config) {
  // ruleid: sensitive-value-logged
  console.log('login', user, password);
  // ruleid: sensitive-value-logged
  console.debug(config.apiKey);
  // ruleid: sensitive-value-logged
  logger.info('token', apiToken);
  // ok: sensitive-value-logged
  console.log('login', user);
  // ok: sensitive-value-logged
  console.log('password reset requested');
}

export function cipherCases(key, iv) {
  // ruleid: node-weak-cipher
  crypto.createCipheriv('des-ecb', key, null);
  // ruleid: node-weak-cipher
  crypto.createCipheriv('aes-128-ecb', key, null);
  // ruleid: node-weak-cipher
  crypto.createCipher('aes-256-cbc', key);
  // ok: node-weak-cipher
  crypto.createCipheriv('aes-256-gcm', key, iv);
}

export function jwtCases(token, key) {
  // ruleid: jwt-none-algorithm
  jwt.verify(token, key, { algorithms: ['none', 'HS256'] });
  // ruleid: jwt-none-algorithm
  jwt.sign({ id: 1 }, key, { algorithm: 'none' });
  // ok: jwt-none-algorithm
  jwt.verify(token, key, { algorithms: ['HS256'] });
}

app.get('/cookie', (req, res) => {
  // ruleid: express-insecure-cookie
  res.cookie('session', 'abc', { httpOnly: false });
  // ruleid: express-insecure-cookie
  res.cookie('session', 'abc', { httpOnly: true, secure: false });
  // ok: express-insecure-cookie
  res.cookie('session', 'abc', { httpOnly: true, secure: true });
});

app.post('/profile', (req, res) => {
  // ruleid: express-mass-assignment
  db.query('UPDATE users SET ?', req.body);
  // ruleid: express-mass-assignment
  User.create(req.body);
  // ok: express-mass-assignment
  User.create({ name: req.body.name });
});

// ruleid: express-admin-route-without-middleware
app.delete('/admin/users/:id', (req, res) => {
  res.end();
});
// ok: express-admin-route-without-middleware
app.delete('/admin/users/:id', requireAdmin, (req, res) => {
  res.end();
});
// ok: express-admin-route-without-middleware
app.get('/health', (req, res) => {
  res.end();
});

// ruleid: server-listens-on-all-interfaces
app.listen(3000, '0.0.0.0');
// ok: server-listens-on-all-interfaces
app.listen(3000, '127.0.0.1');
