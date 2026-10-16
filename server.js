require("dotenv").config();
const path = require("path");
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const IS_PROD = process.env.NODE_ENV === "production";
const GROQ_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL || "openai/gpt-oss-120b";
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET belum diisi (minimal 32 karakter).");
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error("DATABASE_URL belum diisi. Buat database PostgreSQL dan masukkan connection string ke .env.");
  process.exit(1);
}
if (!GROQ_KEY) console.warn("PERINGATAN: GROQ_API_KEY belum diisi, fitur chat AI belum aktif.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(20) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      suspended BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS conversations (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'Chat baru',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_conversations_user_id ON conversations(user_id);
    CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages(conversation_id);
  `);
  // Upgrade an older PostgreSQL schema safely if it already exists.
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended BOOLEAN NOT NULL DEFAULT FALSE");
}

app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false, message: { error: "Terlalu banyak percobaan. Coba lagi 15 menit lagi." } });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false, message: { error: "Kamu ngirim terlalu cepat. Tunggu sebentar ya." } });
const USERNAME_RE = /^[A-Za-z0-9_.]{3,20}$/;
const DUMMY_HASH = bcrypt.hashSync("password-palsu", 12);

function setSession(res, user) {
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
  res.cookie("nexa_token", token, { httpOnly: true, sameSite: "lax", secure: IS_PROD, maxAge: 7 * 24 * 60 * 60 * 1000 });
}
async function requireAuth(req, res, next) {
  try {
    const payload = jwt.verify(req.cookies.nexa_token, JWT_SECRET);
    const result = await pool.query("SELECT id, username, role, suspended FROM users WHERE id = $1", [payload.id]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Belum login." });
    if (user.suspended) return res.status(403).json({ error: "Akun diblokir. Hubungi admin." });
    req.user = user;
    next();
  } catch (err) {
    if (err && err.name !== "JsonWebTokenError" && err.name !== "TokenExpiredError") console.error(err);
    res.status(401).json({ error: "Belum login." });
  }
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Khusus admin." });
    next();
  });
}
const asyncRoute = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

app.post("/api/register", authLimiter, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "Data tidak valid." });
  if (!USERNAME_RE.test(username)) return res.status(400).json({ error: "Username 3-20 karakter: huruf, angka, titik, atau underscore." });
  if (password.length < 8 || Buffer.byteLength(password) > 72) return res.status(400).json({ error: "Password minimal 8 karakter." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query("INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, role", [username, hash]);
    const user = result.rows[0]; setSession(res, user); res.json({ username: user.username });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Username sudah dipakai." });
    console.error(err); res.status(500).json({ error: "Terjadi kesalahan di server." });
  }
}));

app.post("/api/login", authLimiter, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "Data tidak valid." });
  try {
    const result = await pool.query("SELECT id, username, password_hash, role, suspended FROM users WHERE username = $1", [username]);
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) return res.status(401).json({ error: "Username atau password salah." });
    if (user.suspended) return res.status(403).json({ error: "Akun diblokir. Hubungi admin." });
    setSession(res, user); res.json({ username: user.username });
  } catch (err) { console.error(err); res.status(500).json({ error: "Terjadi kesalahan di server." }); }
}));
app.post("/api/logout", (req, res) => { res.clearCookie("nexa_token", { httpOnly: true, sameSite: "lax", secure: IS_PROD }); res.json({ ok: true }); });
app.get("/api/me", requireAuth, (req, res) => res.json({ username: req.user.username, role: req.user.role }));

app.get("/api/conversations", requireAuth, asyncRoute(async (req, res) => {
  const r = await pool.query("SELECT id, title, created_at FROM conversations WHERE user_id = $1 ORDER BY id DESC LIMIT 100", [req.user.id]); res.json(r.rows);
}));
app.get("/api/conversations/:id/messages", requireAuth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id); if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Data tidak valid." });
  const c = await pool.query("SELECT id, title FROM conversations WHERE id = $1 AND user_id = $2", [id, req.user.id]);
  if (!c.rows[0]) return res.status(404).json({ error: "Percakapan tidak ditemukan." });
  const m = await pool.query("SELECT role, content FROM messages WHERE conversation_id = $1 ORDER BY id", [id]); res.json({ title: c.rows[0].title, messages: m.rows });
}));
app.delete("/api/conversations/:id", requireAuth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id); if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Data tidak valid." });
  const r = await pool.query("DELETE FROM conversations WHERE id = $1 AND user_id = $2", [id, req.user.id]);
  if (!r.rowCount) return res.status(404).json({ error: "Percakapan tidak ditemukan." }); res.json({ ok: true });
}));

app.get("/api/admin/stats", requireAdmin, asyncRoute(async (req, res) => {
  const r = await pool.query(`SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM conversations) AS conversations, (SELECT COUNT(*) FROM messages) AS messages, (SELECT COUNT(*) FROM users WHERE suspended = TRUE) AS suspended`);
  const row = r.rows[0]; res.json(Object.fromEntries(Object.entries(row).map(([k,v]) => [k, Number(v)])));
}));
app.get("/api/admin/usage", requireAdmin, asyncRoute(async (req, res) => {
  const r = await pool.query(`SELECT to_char(day::date, 'YYYY-MM-DD') AS day, messages, new_users AS "newUsers" FROM (SELECT d.day, COALESCE(m.n,0)::int AS messages, COALESCE(u.n,0)::int AS new_users FROM generate_series((NOW() AT TIME ZONE 'Asia/Jakarta')::date - 13, (NOW() AT TIME ZONE 'Asia/Jakarta')::date, interval '1 day') d(day) LEFT JOIN (SELECT (created_at AT TIME ZONE 'Asia/Jakarta')::date AS day, COUNT(*) n FROM messages WHERE role='user' AND created_at >= NOW() - INTERVAL '15 days' GROUP BY 1) m ON m.day=d.day::date LEFT JOIN (SELECT (created_at AT TIME ZONE 'Asia/Jakarta')::date AS day, COUNT(*) n FROM users WHERE created_at >= NOW() - INTERVAL '15 days' GROUP BY 1) u ON u.day=d.day::date) q ORDER BY day`);
  res.json({ days: r.rows.map(x=>x.day), messages: r.rows.map(x=>Number(x.messages)), newUsers: r.rows.map(x=>Number(x.newUsers)) });
}));
app.get("/api/admin/users", requireAdmin, asyncRoute(async (req, res) => {
  const r = await pool.query(`SELECT u.id, u.username, u.role, u.suspended, u.created_at, COUNT(c.id)::int AS conversations FROM users u LEFT JOIN conversations c ON c.user_id=u.id GROUP BY u.id ORDER BY u.id DESC`); res.json(r.rows);
}));
app.get("/api/admin/users/:id/conversations", requireAdmin, asyncRoute(async (req, res) => {
  const id=Number(req.params.id); if (!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:"Data tidak valid."});
  const exists=await pool.query("SELECT id FROM users WHERE id=$1",[id]); if(!exists.rowCount) return res.status(404).json({error:"Pengguna tidak ditemukan."});
  const r=await pool.query(`SELECT c.id,c.title,c.created_at,COUNT(m.id)::int AS messages FROM conversations c LEFT JOIN messages m ON m.conversation_id=c.id WHERE c.user_id=$1 GROUP BY c.id ORDER BY c.id DESC LIMIT 200`,[id]); res.json(r.rows);
}));
app.get("/api/admin/conversations/:id/messages", requireAdmin, asyncRoute(async (req,res)=>{
  const id=Number(req.params.id); if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:"Data tidak valid."});
  const c=await pool.query("SELECT c.id,c.title,u.username FROM conversations c JOIN users u ON u.id=c.user_id WHERE c.id=$1",[id]); if(!c.rows[0]) return res.status(404).json({error:"Percakapan tidak ditemukan."});
  const m=await pool.query("SELECT role,content FROM messages WHERE conversation_id=$1 ORDER BY id",[id]); res.json({title:c.rows[0].title,username:c.rows[0].username,messages:m.rows});
}));
app.post("/api/admin/users/:id/suspend", requireAdmin, asyncRoute(async (req,res)=>{
  const id=Number(req.params.id), {suspended}=req.body||{}; if(!Number.isSafeInteger(id)||id<1||typeof suspended!=="boolean") return res.status(400).json({error:"Data tidak valid."});
  if(String(id)===String(req.user.id)) return res.status(403).json({error:"Kamu tidak bisa memblokir akunmu sendiri."});
  const r=await pool.query("SELECT id,role FROM users WHERE id=$1",[id]); const target=r.rows[0]; if(!target) return res.status(404).json({error:"Pengguna tidak ditemukan."});
  if(target.role==="admin") return res.status(403).json({error:"Akun admin tidak bisa diblokir."});
  await pool.query("UPDATE users SET suspended=$1 WHERE id=$2",[suspended,id]); res.json({ok:true});
}));
app.post("/api/admin/users/:id/reset-password", requireAdmin, asyncRoute(async (req,res)=>{
  const id=Number(req.params.id), {password}=req.body||{}; if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:"Data tidak valid."});
  if(typeof password!=="string"||password.length<8||Buffer.byteLength(password)>72) return res.status(400).json({error:"Password baru minimal 8 karakter."});
  const r=await pool.query("SELECT id,role FROM users WHERE id=$1",[id]); const target=r.rows[0]; if(!target) return res.status(404).json({error:"Pengguna tidak ditemukan."});
  if(target.role==="admin"&&String(target.id)!==String(req.user.id)) return res.status(403).json({error:"Tidak bisa mereset password admin lain."});
  await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2",[await bcrypt.hash(password,12),id]); res.json({ok:true});
}));
app.delete("/api/admin/users/:id", requireAdmin, asyncRoute(async (req,res)=>{
  const id=Number(req.params.id); if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:"Data tidak valid."});
  if(String(id)===String(req.user.id)) return res.status(403).json({error:"Kamu tidak bisa menghapus akunmu sendiri."});
  const r=await pool.query("SELECT id,role FROM users WHERE id=$1",[id]); const target=r.rows[0]; if(!target) return res.status(404).json({error:"Pengguna tidak ditemukan."});
  if(target.role==="admin") return res.status(403).json({error:"Akun admin tidak bisa dihapus dari panel."});
  await pool.query("DELETE FROM users WHERE id=$1",[id]); res.json({ok:true});
}));
app.get("/admin", (req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));

const SYSTEM_PROMPT = "Kamu adalah Nexa, asisten AI yang ramah dan enak diajak ngobrol. Jawab dalam bahasa yang dipakai pengguna. Kalau pengguna pakai bahasa Indonesia, balas dengan bahasa Indonesia santai dan natural, tidak kaku seperti robot. Jawab ringkas dan jelas, kecuali pengguna minta penjelasan panjang. Tulis teks biasa tanpa simbol markdown seperti ** atau ##. Kalau tidak tahu, bilang jujur.";
app.post("/api/chat", requireAuth, chatLimiter, asyncRoute(async (req,res)=>{
  if(!GROQ_KEY) return res.status(503).json({error:"AI belum dikonfigurasi di server."});
  const {conversationId,message}=req.body||{}; if(typeof message!=="string"||!message.trim()) return res.status(400).json({error:"Data tidak valid."});
  const text=message.trim(); if(text.length>4000) return res.status(400).json({error:"Pesan terlalu panjang (maks 4000 karakter)."});
  let convId=null;
  if(conversationId!==null&&conversationId!==undefined){ convId=Number(conversationId); if(!Number.isSafeInteger(convId)||convId<1) return res.status(400).json({error:"Data tidak valid."}); const own=await pool.query("SELECT id FROM conversations WHERE id=$1 AND user_id=$2",[convId,req.user.id]); if(!own.rowCount) return res.status(404).json({error:"Percakapan tidak ditemukan."}); }
  let past=[]; if(convId){ const r=await pool.query("SELECT role,content FROM messages WHERE conversation_id=$1 ORDER BY id DESC LIMIT 10",[convId]); past=r.rows.reverse(); while(past.length&&past[0].role!=="user") past.shift(); }
  const chatMessages=[{role:"system",content:SYSTEM_PROMPT},...past.map(m=>({role:m.role,content:m.content})),{role:"user",content:text}];
  const controller=new AbortController(); res.on("close",()=>{if(!res.writableEnded) controller.abort();}); const signal=AbortSignal.any([controller.signal,AbortSignal.timeout(60000)]);
  const body={model:GROQ_MODEL,messages:chatMessages,stream:true,temperature:0.8,max_completion_tokens:1500}; if(GROQ_MODEL.startsWith("openai/gpt-oss")) body.reasoning_effort="low";
  let upstream;
  try{ upstream=await fetch("https://api.groq.com/openai/v1/chat/completions",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+GROQ_KEY},body:JSON.stringify(body),signal}); }
  catch(err){if(controller.signal.aborted)return; console.error("Gagal menghubungi Groq:",err.message); return res.status(502).json({error:"Tidak bisa menghubungi AI. Coba lagi nanti."});}
  if(!upstream.ok){const detail=await upstream.text().catch(()=>""); console.error("Groq error",upstream.status,detail.slice(0,500)); if(upstream.status===429)return res.status(429).json({error:"Nexa lagi kebanjiran permintaan. Coba lagi sebentar."}); if(upstream.status===401)return res.status(502).json({error:"Kunci AI salah. Cek GROQ_API_KEY."}); return res.status(502).json({error:"AI bermasalah. Cek pesan error di terminal server."});}
  let createdConv=false, userMsgId=null; const client=await pool.connect();
  try{
    await client.query("BEGIN");
    if(!convId){const title=text.replace(/\s+/g," "); const c=await client.query("INSERT INTO conversations(user_id,title) VALUES($1,$2) RETURNING id",[req.user.id,title.slice(0,40)+(title.length>40?"...":"")]); convId=Number(c.rows[0].id); createdConv=true;}
    const m=await client.query("INSERT INTO messages(conversation_id,role,content) VALUES($1,'user',$2) RETURNING id",[convId,text]); userMsgId=m.rows[0].id;
    await client.query("COMMIT");
  }catch(err){await client.query("ROLLBACK"); console.error(err); return res.status(500).json({error:"Gagal menyimpan pesan."});}finally{client.release();}
  const rollback=async()=>{if(createdConv) await pool.query("DELETE FROM conversations WHERE id=$1",[convId]); else if(userMsgId) await pool.query("DELETE FROM messages WHERE id=$1",[userMsgId]);};
  res.setHeader("X-Conversation-Id",String(convId)); res.setHeader("Content-Type","text/plain; charset=utf-8"); res.setHeader("Cache-Control","no-cache"); res.setHeader("X-Accel-Buffering","no"); res.flushHeaders();
  let full="";
  try{const decoder=new TextDecoder();let buffer="";for await(const chunk of upstream.body){buffer+=decoder.decode(chunk,{stream:true});const lines=buffer.split("\n");buffer=lines.pop();for(const line of lines){if(!line.startsWith("data:"))continue;const data=line.slice(5).trim();if(!data||data==="[DONE]")continue;try{const json=JSON.parse(data);const piece=json.choices?.[0]?.delta?.content;if(piece){res.write(piece);full+=piece;}}catch(e){}}} if(!full)res.write("Maaf, Nexa nggak bisa jawab itu. Coba tanya dengan cara lain ya.");}
  catch(err){if(!controller.signal.aborted){console.error("Stream error:",err.message);res.write(full?"\n\n[Koneksi terputus]":"Maaf, ada gangguan. Coba lagi ya.");}}
  const answer=full.trim(); if(answer) await pool.query("INSERT INTO messages(conversation_id,role,content) VALUES($1,'assistant',$2)",[convId,answer]); else await rollback(); res.end();
}));
app.get("/api/health", asyncRoute(async (req,res)=>{const r=await pool.query("SELECT COUNT(*)::int AS n FROM users");res.json({status:"ok",app:"Nexa AI",users:r.rows[0].n});}));
app.use((err,req,res,next)=>{console.error("Unhandled server error:",err);if(res.headersSent)return next(err);res.status(500).json({error:"Terjadi kesalahan di server."});});

initDatabase().then(()=>{
  app.listen(PORT,()=>console.log("Nexa AI jalan di port "+PORT));
}).catch(err=>{console.error("Gagal menyiapkan database PostgreSQL:",err);process.exit(1);});
process.on("SIGTERM",async()=>{await pool.end();process.exit(0);});
