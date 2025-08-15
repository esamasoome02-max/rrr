
// ESM server.js (works with "type": "module" in package.json)
import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';
import { v4 as uuid } from 'uuid';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'db.json');

// ---------- simple JSON "DB" ----------
function ensureDB() {
  if (!fs.existsSync(DB_PATH)) {
    const init = { users: [], transactions: [], debts: [], settings: {
      paymentMethods: ["cash","bank","card","cheque","other"],
      incomeCategories: ["sales","subscriptions","services","interest","other"],
      expenseCategories: ["salary","rent","maintenance","logistics","purchases","internet","energy","tax","marketing","other"],
      employees: []
    }};
    fs.writeFileSync(DB_PATH, JSON.stringify(init, null, 2));
  }
}
function readDB() { ensureDB(); return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8')); }
function writeDB(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }

function createToken(user) { return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' }); }
function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.get('/', (req,res)=> res.json({ ok:true, service:'finance-api', docs:'/docs' }));
app.get('/docs', (req,res)=> res.type('text').send(`See README`));

// ---- auth ----
app.post('/auth/register', (req,res)=>{
  const { email, password, company } = req.body || {};
  if (!email || !password) return res.status(400).json({ error:'email and password required' });
  const db = readDB();
  if (db.users.find(u=>u.email.toLowerCase()===String(email).toLowerCase())) {
    return res.status(400).json({ error:'email already exists' });
  }
  const user = { id: uuid(), email, company: company||null, passwordHash: bcrypt.hashSync(password,10), createdAt: new Date().toISOString() };
  db.users.push(user); writeDB(db);
  res.json({ token: createToken(user), user: { id:user.id, email:user.email, company:user.company } });
});

app.post('/auth/login', (req,res)=>{
  const { email, password } = req.body || {};
  const db = readDB();
  const user = db.users.find(u=>u.email.toLowerCase()===String(email||'').toLowerCase());
  if (!user) return res.status(400).json({ error:'invalid credentials' });
  const ok = bcrypt.compareSync(password||'', user.passwordHash);
  if (!ok) return res.status(400).json({ error:'invalid credentials' });
  res.json({ token: createToken(user), user: { id:user.id, email:user.email, company:user.company } });
});

app.get('/me', auth, (req,res)=>{
  const db = readDB();
  const user = db.users.find(u=>u.id===req.user.id);
  res.json({ id:user.id, email:user.email, company:user.company });
});

// ---- transactions ----
app.get('/transactions', auth, (req,res)=>{
  const { type, frm, to, employee } = req.query;
  const db = readDB();
  let list = db.transactions;
  if (type) list = list.filter(t=>t.type===type);
  if (employee) list = list.filter(t=>String(t.employee||'').toLowerCase()===String(employee).toLowerCase());
  if (frm) list = list.filter(t=>new Date(t.date) >= new Date(frm));
  if (to)  list = list.filter(t=>new Date(t.date) <= new Date(to));
  res.json(list);
});

app.post('/transactions', auth, (req,res)=>{
  const t = req.body || {};
  if (!t.date || !t.type || !t.amount) return res.status(400).json({ error:'date, type, amount required' });
  if (!['income','expense'].includes(t.type)) return res.status(400).json({ error:'type must be income or expense' });
  const taxValue = Number(t.amount) * Number(t.taxPercent||0) / 100;
  const row = {
    id: uuid(), date: t.date, type: t.type, category: t.category || null,
    description: t.description || null, paymentMethod: t.paymentMethod || null,
    reference: t.reference || null, project: t.project || null,
    employee: t.employee || null, party: t.party || null,
    amount: Number(t.amount), taxPercent: Number(t.taxPercent||0), taxValue,
    total: (t.type==='expense'? -1:1) * (Number(t.amount)+taxValue),
    createdBy: req.user.id, createdAt: new Date().toISOString()
  };
  const db = readDB(); db.transactions.push(row); writeDB(db); res.json(row);
});

app.put('/transactions/:id', auth, (req,res)=>{
  const db = readDB();
  const idx = db.transactions.findIndex(x=>x.id===req.params.id);
  if (idx===-1) return res.status(404).json({ error:'not found' });
  const t = { ...db.transactions[idx], ...req.body };
  t.taxValue = Number(t.amount) * Number(t.taxPercent||0) / 100;
  t.total = (t.type==='expense'? -1:1) * (Number(t.amount)+t.taxValue);
  db.transactions[idx] = t; writeDB(db); res.json(t);
});

app.delete('/transactions/:id', auth, (req,res)=>{
  const db = readDB(); const before = db.transactions.length;
  db.transactions = db.transactions.filter(x=>x.id!==req.params.id);
  writeDB(db); res.json({ ok:true, deleted: before - db.transactions.length });
});

// ---- debts ----
app.get('/debts', auth, (req,res)=> res.json(readDB().debts));

app.post('/debts', auth, (req,res)=>{
  const d = req.body || {};
  if (!d.date || !d.employee || !d.kind) return res.status(400).json({ error:'date, employee, kind required' });
  const row = { id: uuid(), date:d.date, employee:d.employee, employeeId:d.employeeId||null,
    kind:d.kind, description:d.description||null, plus:Number(d.plus||0), minus:Number(d.minus||0),
    createdBy:req.user.id, createdAt:new Date().toISOString() };
  const db = readDB(); db.debts.push(row); writeDB(db); res.json(row);
});

app.put('/debts/:id', auth, (req,res)=>{
  const db = readDB();
  const idx = db.debts.findIndex(x=>x.id===req.params.id);
  if (idx===-1) return res.status(404).json({ error:'not found' });
  db.debts[idx] = { ...db.debts[idx], ...req.body }; writeDB(db); res.json(db.debts[idx]);
});

app.delete('/debts/:id', auth, (req,res)=>{
  const db = readDB(); const before = db.debts.length;
  db.debts = db.debts.filter(x=>x.id!==req.params.id);
  writeDB(db); res.json({ ok:true, deleted: before - db.debts.length });
});

app.get('/debts/balances', auth, (req,res)=>{
  const db = readDB();
  const map = {};
  for (const d of db.debts) {
    const k = d.employee || '—';
    if (!map[k]) map[k] = { employee:k, advances:0, repays:0, balance:0 };
    map[k].advances += Number(d.plus||0);
    map[k].repays += Number(d.minus||0);
    map[k].balance = map[k].advances - map[k].repays;
  }
  res.json(Object.values(map));
});

// ---- settings ----
app.get('/settings', auth, (req,res)=> res.json(readDB().settings || {}));
app.put('/settings', auth, (req,res)=>{
  const db = readDB(); db.settings = { ...(db.settings||{}), ...(req.body||{}) }; writeDB(db); res.json(db.settings);
});

// ---- export/import ----
app.get('/export', auth, (req,res)=> res.json(readDB()));
app.post('/import', auth, (req,res)=>{
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error:'data required' });
  writeDB(data); res.json({ ok:true });
});

app.listen(PORT, ()=> console.log(`Finance API (ESM) running on ${PORT}`));
