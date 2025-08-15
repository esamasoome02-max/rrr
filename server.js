import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import fs from 'fs';
import path from 'path';

const app = express();
app.use(cors());
app.use(express.json({limit:'5mb'}));

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-secret';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || ''; // for backup endpoints
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './data.db';

// ensure folder exists
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = await open({ filename: DB_PATH, driver: sqlite3.Database });

// bootstrap schema
const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  company_name TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS settings (
  user_id INTEGER PRIMARY KEY,
  currency TEXT DEFAULT 'ر.س',
  tax_income REAL DEFAULT 15.0,
  tax_expense REAL DEFAULT 15.0,
  monthly_expense_cap REAL DEFAULT 50000.0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('income','expense')),
  category TEXT NOT NULL,
  base REAL NOT NULL,
  tax REAL NOT NULL,
  total REAL NOT NULL,
  employee TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tx_user_date ON transactions(user_id,date);

CREATE TABLE IF NOT EXISTS debts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  employee TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('advance','repay')),
  amount REAL NOT NULL,
  delta REAL NOT NULL,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_debt_user_date ON debts(user_id,date);
`;
await db.exec(schema);

function sign(user){ return jwt.sign({uid:user.id,email:user.email}, JWT_SECRET, {expiresIn:'7d'}); }
function auth(req,res,next){
  const h=req.headers.authorization||''; const tok=h.startsWith('Bearer ')? h.slice(7):'';
  try{ const p=jwt.verify(tok, JWT_SECRET); req.user=p; next(); }catch(e){ return res.status(401).json({error:'UNAUTHORIZED'}); }
}
function adminOnly(req,res,next){
  if (!ADMIN_TOKEN || req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'UNAUTHORIZED' });
  }
  next();
}

// ---- Auth ----
app.post('/auth/register', async (req,res)=>{
  const {email,password,company_name} = req.body||{};
  if(!email || !password) return res.status(400).json({error:'email & password required'});
  const hash = await bcrypt.hash(password, 10);
  try{
    const r = await db.run('INSERT INTO users(email,password_hash,company_name) VALUES (?,?,?)', [email.trim().toLowerCase(), hash, company_name||null]);
    await db.run('INSERT INTO settings(user_id) VALUES (?)', [r.lastID]);
    const user = await db.get('SELECT id,email,company_name FROM users WHERE id=?',[r.lastID]);
    return res.json({token:sign(user), user});
  }catch(e){
    if(String(e).includes('UNIQUE')) return res.status(409).json({error:'EMAIL_IN_USE'});
    return res.status(500).json({error:'REG_FAILED', details:String(e)});
  }
});

app.post('/auth/login', async (req,res)=>{
  const {email,password} = req.body||{};
  const user = await db.get('SELECT * FROM users WHERE email=?',[String(email||'').trim().toLowerCase()]);
  if(!user) return res.status(401).json({error:'INVALID_CREDENTIALS'});
  const ok = await bcrypt.compare(password||'', user.password_hash);
  if(!ok) return res.status(401).json({error:'INVALID_CREDENTIALS'});
  return res.json({token:sign(user), user:{id:user.id,email:user.email,company_name:user.company_name}});
});

app.get('/me', auth, async (req,res)=>{
  const user = await db.get('SELECT id,email,company_name FROM users WHERE id=?',[req.user.uid]);
  const settings = await db.get('SELECT currency,tax_income,tax_expense,monthly_expense_cap FROM settings WHERE user_id=?',[req.user.uid]);
  res.json({user,settings});
});

// ---- Settings ----
app.get('/settings', auth, async (req,res)=>{
  const s = await db.get('SELECT currency,tax_income,tax_expense,monthly_expense_cap FROM settings WHERE user_id=?',[req.user.uid]);
  res.json(s);
});
app.put('/settings', auth, async (req,res)=>{
  const {currency,tax_income,tax_expense,monthly_expense_cap} = req.body||{};
  await db.run('UPDATE settings SET currency=COALESCE(?,currency), tax_income=COALESCE(?,tax_income), tax_expense=COALESCE(?,tax_expense), monthly_expense_cap=COALESCE(?,monthly_expense_cap) WHERE user_id=?',
    [currency, tax_income, tax_expense, monthly_expense_cap, req.user.uid]);
  const s = await db.get('SELECT currency,tax_income,tax_expense,monthly_expense_cap FROM settings WHERE user_id=?',[req.user.uid]);
  res.json(s);
});

// ---- Transactions ----
app.get('/transactions', auth, async (req,res)=>{
  const rows = await db.all('SELECT * FROM transactions WHERE user_id=? ORDER BY date DESC, created_at DESC', [req.user.uid]);
  res.json(rows);
});
app.post('/transactions', auth, async (req,res)=>{
  const {date,type,category,base,employee,notes} = req.body||{};
  if(!date || !type || !category || base==null) return res.status(400).json({error:'Missing fields'});
  const s = await db.get('SELECT tax_income,tax_expense FROM settings WHERE user_id=?',[req.user.uid]);
  const rate = (type==='income'? (s.tax_income||0) : (s.tax_expense||0))/100.0;
  const tax = Math.round((Number(base)||0)*rate*100)/100;
  const total = Math.round(((Number(base)||0)+tax)*100)/100;
  const r = await db.run('INSERT INTO transactions(user_id,date,type,category,base,tax,total,employee,notes) VALUES (?,?,?,?,?,?,?,?,?)',
    [req.user.uid,date,type,category,base,tax,total,employee||null,notes||null]);
  const row = await db.get('SELECT * FROM transactions WHERE id=?',[r.lastID]);
  res.json(row);
});
app.put('/transactions/:id', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const t = await db.get('SELECT * FROM transactions WHERE id=? AND user_id=?',[id, req.user.uid]);
  if(!t) return res.status(404).json({error:'NOT_FOUND'});
  const newVals = {...t, ...req.body};
  const s = await db.get('SELECT tax_income,tax_expense FROM settings WHERE user_id=?',[req.user.uid]);
  const rate = (newVals.type==='income'? (s.tax_income||0) : (s.tax_expense||0))/100.0;
  const base = Number(newVals.base||0);
  const tax = Math.round(base*rate*100)/100;
  const total = Math.round((base+tax)*100)/100;
  await db.run('UPDATE transactions SET date=?,type=?,category=?,base=?,tax=?,total=?,employee=?,notes=? WHERE id=? AND user_id=?',
    [newVals.date,newVals.type,newVals.category,base,tax,total,newVals.employee||null,newVals.notes||null,id,req.user.uid]);
  const row = await db.get('SELECT * FROM transactions WHERE id=?',[id]);
  res.json(row);
});
app.delete('/transactions/:id', auth, async (req,res)=>{
  await db.run('DELETE FROM transactions WHERE id=? AND user_id=?',[req.params.id, req.user.uid]);
  res.json({ok:true});
});

// ---- Debts ----
app.get('/debts', auth, async (req,res)=>{
  const rows = await db.all('SELECT * FROM debts WHERE user_id=? ORDER BY date ASC, created_at ASC', [req.user.uid]);
  res.json(rows);
});
app.post('/debts', auth, async (req,res)=>{
  const {date,employee,kind,amount,notes} = req.body||{};
  if(!date||!employee||!kind||amount==null) return res.status(400).json({error:'Missing fields'});
  const amt = Number(amount||0); const delta = (kind==='advance'? +amt : -amt);
  const r = await db.run('INSERT INTO debts(user_id,date,employee,kind,amount,delta,notes) VALUES (?,?,?,?,?,?,?)',
    [req.user.uid,date,employee,kind,amt,delta,notes||null]);
  const row = await db.get('SELECT * FROM debts WHERE id=?',[r.lastID]);
  res.json(row);
});
app.put('/debts/:id', auth, async (req,res)=>{
  const id = Number(req.params.id);
  const d = await db.get('SELECT * FROM debts WHERE id=? AND user_id=?',[id, req.user.uid]);
  if(!d) return res.status(404).json({error:'NOT_FOUND'});
  const newVals = {...d, ...req.body};
  const amt = Number(newVals.amount||0); const delta = (newVals.kind==='advance'? +amt : -amt);
  await db.run('UPDATE debts SET date=?,employee=?,kind=?,amount=?,delta=?,notes=? WHERE id=? AND user_id=?',
    [newVals.date,newVals.employee,newVals.kind,amt,delta,newVals.notes||null,id,req.user.uid]);
  const row = await db.get('SELECT * FROM debts WHERE id=?',[id]);
  res.json(row);
});
app.delete('/debts/:id', auth, async (req,res)=>{
  await db.run('DELETE FROM debts WHERE id=? AND user_id=?',[req.params.id, req.user.uid]);
  res.json({ok:true});
});

// ---- Admin backup endpoints (protected by X-Admin-Token) ----
app.get('/admin/backup/json', adminOnly, async (req,res)=>{
  const users = await db.all('SELECT id,email,company_name,created_at FROM users');
  const settings = await db.all('SELECT * FROM settings');
  const transactions = await db.all('SELECT * FROM transactions');
  const debts = await db.all('SELECT * FROM debts');
  res.setHeader('Content-Disposition', 'attachment; filename="backup.json"');
  res.json({ users, settings, transactions, debts, exported_at: new Date().toISOString() });
});
app.get('/admin/backup/sqlite', adminOnly, async (req,res)=>{
  res.setHeader('Content-Disposition', 'attachment; filename="data.db"');
  res.sendFile(path.resolve(DB_PATH));
});

// ---- Health ----
app.get('/', (req,res)=> res.json({ok:true, service:'finance-dashboard-api', db: DB_PATH}));

app.listen(PORT, ()=> console.log('API listening on port', PORT));
