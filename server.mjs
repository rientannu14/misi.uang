import http from 'node:http';
import { readFileSync, existsSync, mkdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { join, dirname, extname, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { networkInterfaces } from 'node:os';

const root=dirname(fileURLToPath(import.meta.url));
const gameRoot=join(root,'misi-uang-kelas');
const dataDir=process.env.DATA_DIR || join(root,'data');
mkdirSync(dataDir,{recursive:true});
const db=new DatabaseSync(join(dataDir,'kelas.db'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, role TEXT NOT NULL, name TEXT NOT NULL, class_name TEXT, roll_no TEXT, pin_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(class_name,roll_no));
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS scores(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, score INTEGER NOT NULL, correct INTEGER NOT NULL, total INTEGER NOT NULL, played_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_scores_user ON scores(user_id,played_at);
CREATE INDEX IF NOT EXISTS idx_users_class ON users(class_name);`);
const hashPassword=p=>{const salt=randomBytes(16).toString('hex');return `${salt}:${scryptSync(p,salt,64).toString('hex')}`};
const verifyPassword=(p,stored)=>{try{const [salt,hex]=stored.split(':');const a=scryptSync(p,salt,64),b=Buffer.from(hex,'hex');return a.length===b.length&&timingSafeEqual(a,b)}catch{return false}};
const clean=s=>String(s??'').trim().replace(/\s+/g,' ');
const isValid=(s,max)=>s.length>0&&s.length<=max&&/^[\p{L}\p{N} .'-]+$/u.test(s);
const json=(res,status,obj)=>{const b=JSON.stringify(obj);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Content-Length':Buffer.byteLength(b),'Cache-Control':'no-store'});res.end(b)};
const cookie=(req,name)=>{const m=(req.headers.cookie||'').match(new RegExp(`(?:^|; )${name}=([^;]+)`));return m?.[1]||''};
const sessionUser=req=>{const token=cookie(req,'misi_session');if(!/^[a-f0-9]{64}$/.test(token))return null;return db.prepare('SELECT u.id,u.role,u.name,u.class_name AS className,u.roll_no AS rollNo FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(createHash('sha256').update(token).digest('hex'),Date.now())||null};
const login=(res,user)=>{const token=randomBytes(32).toString('hex'),expires=Date.now()+(user.role==='teacher'?8:7*24)*3600000;db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(createHash('sha256').update(token).digest('hex'),user.id,expires);res.setHeader('Set-Cookie',`misi_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor((expires-Date.now())/1000)}${process.env.NODE_ENV==='production'?'; Secure':''}`)};
const limited=new Map();function rateLimit(req){const ip=req.socket.remoteAddress||'unknown',now=Date.now(),v=limited.get(ip)||{count:0,until:now+60000};if(now>v.until){v.count=0;v.until=now+60000}v.count++;limited.set(ip,v);return v.count>40}
async function body(req){let chunks=[],size=0;for await(const c of req){size+=c.length;if(size>8192)throw Error('Permintaan terlalu besar.');chunks.push(c)}try{return JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{throw Error('Data tidak valid.')}}
function replay(events){
 if(!Array.isArray(events)||events.length<17||events.length>500)throw Error('Riwayat permainan tidak valid.');
 const answers=[[1,0,0],null,[0,0,0,0],[0,0,0,0,0]];
 let level=0,round=0,hearts=3,combo=0,score=0,correct=0,levelStartScore=0,levelStartCorrect=0;
 for(const event of events){
  if(!Array.isArray(event)||event.length<1||event.length>2||level>3)throw Error('Urutan permainan tidak valid.');
  if(hearts===0){if(event[0]!=='retry'||event.length!==1)throw Error('Pulau harus diulang.');hearts=3;combo=0;score=levelStartScore;correct=levelStartCorrect;round=0;continue}
  if(event.length!==2||!Number.isInteger(event[1])||event[1]<0||event[1]>4)throw Error('Jawaban tidak valid.');
  const order=level===1;if(event[0]!== (order?'order':'answer'))throw Error('Jenis tantangan tidak sesuai.');
  let ok=event[1]===(order?round:answers[level][round]);
  if(ok){combo++;correct++;score+=100+Math.min(combo-1,3)*25;if(order)round++}else{hearts--;combo=0}
  if(!order)round++;
  const n=order?5:answers[level].length;
  if(round===n&&hearts>0){level++;round=0;hearts=3;levelStartScore=score;levelStartCorrect=correct}
 }
 if(level!==4)throw Error('Permainan belum selesai.');return {score,correct};
}
const fail=(res,status,message)=>json(res,status,{error:message});
const profile=u=>({role:u.role,name:u.name,className:u.className,rollNo:u.rollNo});
async function setup(){if(db.prepare("SELECT id FROM users WHERE role='teacher'").get()){console.log('Akun guru sudah ada. Setup dihentikan.');return}const rl=createInterface({input,output});try{const name=clean(await rl.question('Nama guru: '));const username=clean(await rl.question('Nama pengguna guru (misalnya guru_ips): ')).toLowerCase();const password=await rl.question('Kata sandi guru (minimal 12 karakter): ');if(!isValid(name,80)||!/^[a-z0-9_]{3,40}$/.test(username)||password.length<12)throw Error('Nama/pengguna tidak valid atau kata sandi kurang dari 12 karakter.');db.prepare('INSERT INTO users(role,name,class_name,roll_no,pin_hash) VALUES(?,?,?,?,?)').run('teacher',name,null,username,hashPassword(password));console.log('Akun guru dibuat. Jalankan: npm start')}finally{rl.close()}}
if(process.argv[2]==='setup'){await setup();process.exit(0)}
if(!db.prepare("SELECT id FROM users WHERE role='teacher'").get()){
 const defaultTeacherName=clean(process.env.TEACHER_NAME||'Guru IPS');
 const defaultUsername=clean(process.env.TEACHER_USERNAME||'guru').toLowerCase();
 const defaultPassword=String(process.env.TEACHER_PASSWORD||'');
 if(process.env.NODE_ENV==='production'){
  if(!isValid(defaultTeacherName,80)||!/^[a-z0-9_]{3,40}$/.test(defaultUsername)||defaultPassword.length<12){
   console.error('Set TEACHER_NAME, TEACHER_USERNAME, and TEACHER_PASSWORD (minimum 12 characters) before starting in production.');
   process.exit(1);
  }
 } else if(defaultPassword.length<12){
  console.warn('Local mode: set TEACHER_PASSWORD or run 1-SETUP-GURU.bat to create a teacher account.');
 }
 if(defaultPassword.length>=12){
  db.prepare('INSERT INTO users(role,name,class_name,roll_no,pin_hash) VALUES(?,?,?,?,?)').run('teacher',defaultTeacherName,null,defaultUsername,hashPassword(defaultPassword));
  console.log(`Akun guru dibuat: username ${defaultUsername}`);
 }
}

const siteHtml=readFileSync(join(root,'index.html'));
const gameHtml=readFileSync(join(gameRoot,'index.html'));
const mimeTypes={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.ico':'image/x-icon','.json':'application/json; charset=utf-8','.txt':'text/plain; charset=utf-8'};
const serveStatic=(res,filePath)=>{if(!existsSync(filePath))return false;const data=readFileSync(filePath);const ext=extname(filePath).toLowerCase();res.writeHead(200,{'Content-Type':mimeTypes[ext]||'application/octet-stream','Cache-Control':'no-store'});res.end(data);return true};
const safeStatic=(base,pathname)=>{const decoded=decodeURIComponent(pathname);const rel=decoded.replace(/^\/+/, '');const target=normalize(join(base,rel));const baseNorm=normalize(base+sep);return target.startsWith(baseNorm)?target:null};
const server=http.createServer(async(req,res)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','SAMEORIGIN');try{
 const url=new URL(req.url,'http://localhost');if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(siteHtml);return}
 if(req.method==='GET'&&(url.pathname==='/misi-uang-kelas'||url.pathname==='/misi-uang-kelas/'||url.pathname==='/misi-uang-kelas/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(gameHtml);return}
 if(req.method==='GET'&&url.pathname.startsWith('/assets/')){const file=safeStatic(join(root,'assets'),url.pathname.slice('/assets/'.length));if(file&&serveStatic(res,file))return;return fail(res,404,'Aset tidak ditemukan.');}
 if(req.method==='GET'&&url.pathname.startsWith('/misi-uang-kelas/')){const file=safeStatic(gameRoot,url.pathname.slice('/misi-uang-kelas/'.length));if(file&&serveStatic(res,file))return;return fail(res,404,'Aset game tidak ditemukan.');}
 if(req.method==='GET'&&url.pathname==='/health'){return json(res,200,{ok:true,service:'misi-uang'})}
 if(req.method==='GET'&&url.pathname==='/api/access-url'){
  const forwarded=String(req.headers['x-forwarded-proto']||'').split(',')[0].trim();
  const host=String(req.headers.host||'');
  let base='';
  if(process.env.PUBLIC_URL) base=String(process.env.PUBLIC_URL).replace(/\/$/,'');
  else if(host && !/^localhost(?::\d+)?$|^127\.0\.0\.1(?::\d+)?$/i.test(host)) base=`${forwarded||'http'}://${host}`;
  else {
   let ip='127.0.0.1';
   outer: for(const group of Object.values(networkInterfaces())) for(const net of group||[]) if(net.family==='IPv4'&&!net.internal){ip=net.address;break outer;}
   base=`http://${ip}:${port}`;
  }
  return json(res,200,{url:`${base}/misi-uang-kelas/`});
 }
 if(!url.pathname.startsWith('/api/'))return fail(res,404,'Halaman tidak ditemukan.');
 if(req.method==='POST'){const origin=req.headers.origin;if(origin&&new URL(origin).host!==req.headers.host)return fail(res,403,'Asal permintaan ditolak.');if(rateLimit(req))return fail(res,429,'Terlalu banyak permintaan. Coba lagi sebentar.');}
 const user=sessionUser(req);
 if(req.method==='GET'&&url.pathname==='/api/me')return json(res,200,{user:user?profile(user):null});
 if(req.method==='POST'&&url.pathname==='/api/student/register'){
  const d=await body(req),name=clean(d.name),className=clean(d.className).toUpperCase(),rollNo=clean(d.rollNo),pin=String(d.pin||'');
  if(!isValid(name,80)||!isValid(className,30)||!isValid(rollNo,10)||!/^\d{4,8}$/.test(pin))return fail(res,400,'Isi nama, kelas, nomor absen, dan PIN 4–8 angka.');
  if(db.prepare('SELECT id FROM users WHERE class_name=? AND roll_no=?').get(className,rollNo))return fail(res,409,'Nomor absen ini sudah terdaftar di kelas tersebut. Silakan masuk.');
  const id=Number(db.prepare('INSERT INTO users(role,name,class_name,roll_no,pin_hash) VALUES(?,?,?,?,?)').run('student',name,className,rollNo,hashPassword(pin)).lastInsertRowid);const u={id,role:'student',name,className,rollNo};login(res,u);return json(res,201,{user:profile(u)})}
 if(req.method==='POST'&&url.pathname==='/api/student/login'){
  const d=await body(req),name=clean(d.name).toLowerCase(),className=clean(d.className).toUpperCase(),rollNo=clean(d.rollNo),pin=String(d.pin||'');const u=db.prepare("SELECT id,role,name,class_name AS className,roll_no AS rollNo,pin_hash AS pinHash FROM users WHERE role='student' AND class_name=? AND roll_no=?").get(className,rollNo);
  if(!u||u.name.toLowerCase()!==name||!verifyPassword(pin,u.pinHash))return fail(res,401,'Data siswa atau PIN belum sesuai.');login(res,u);return json(res,200,{user:profile(u)})}
 if(req.method==='POST'&&url.pathname==='/api/teacher/login'){
  const d=await body(req),username=clean(d.username).toLowerCase(),password=String(d.password||'');const u=db.prepare("SELECT id,role,name,class_name AS className,roll_no AS rollNo,pin_hash AS pinHash FROM users WHERE role='teacher' AND roll_no=?").get(username);if(!u||!verifyPassword(password,u.pinHash))return fail(res,401,'Akun guru atau kata sandi salah.');login(res,u);return json(res,200,{user:profile(u)})}
 if(req.method==='POST'&&url.pathname==='/api/logout'){const token=cookie(req,'misi_session');if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(createHash('sha256').update(token).digest('hex'));res.setHeader('Set-Cookie','misi_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');return json(res,200,{ok:true})}
 if(!user)return fail(res,401,'Silakan masuk dahulu.');
 if(req.method==='POST'&&url.pathname==='/api/score'){
  if(user.role!=='student')return fail(res,403,'Khusus siswa.');const d=await body(req);let result;try{result=replay(d.events)}catch(e){return fail(res,400,e.message)}if(d.score!==result.score||d.correct!==result.correct||d.total!==17)return fail(res,400,'Skor tidak sesuai dengan jawaban.');db.prepare('INSERT INTO scores(user_id,score,correct,total) VALUES(?,?,?,?)').run(user.id,result.score,result.correct,17);return json(res,201,{ok:true,score:result.score})}
 if(req.method==='GET'&&url.pathname==='/api/my-scores'){
  if(user.role!=='student')return fail(res,403,'Khusus siswa.');return json(res,200,{scores:db.prepare('SELECT score,correct,total,played_at AS playedAt FROM scores WHERE user_id=? ORDER BY id DESC LIMIT 50').all(user.id)})}
 if(req.method==='GET'&&url.pathname==='/api/classes'){
  if(user.role!=='teacher')return fail(res,403,'Khusus guru.');return json(res,200,{classes:db.prepare("SELECT DISTINCT class_name AS name FROM users WHERE role='student' ORDER BY class_name").all().map(x=>x.name)})}
 if(req.method==='GET'&&(url.pathname==='/api/teacher/scores'||url.pathname==='/api/teacher/export')){
  if(user.role!=='teacher')return fail(res,403,'Khusus guru.');const className=clean(url.searchParams.get('className')).toUpperCase();const rows=db.prepare(`SELECT u.id,u.name,u.class_name AS className,u.roll_no AS rollNo,COUNT(s.id) AS plays,MAX(s.score) AS bestScore,ROUND(AVG(s.score),0) AS avgScore,MAX(s.played_at) AS lastPlayed FROM users u LEFT JOIN scores s ON s.user_id=u.id WHERE u.role='student' AND (?='' OR u.class_name=?) GROUP BY u.id ORDER BY u.class_name,CAST(u.roll_no AS INTEGER),u.name`).all(className,className);
  if(url.pathname.endsWith('/export')){const cell=v=>'"'+String(v??'').replaceAll('"','""')+'"';const csv='\uFEFF'+[['Kelas','No. absen','Nama','Jumlah main','Skor terbaik','Rata-rata skor','Terakhir bermain'],...rows.map(r=>[r.className,r.rollNo,r.name,r.plays,r.bestScore??'',r.avgScore??'',r.lastPlayed??''])].map(a=>a.map(cell).join(',')).join('\r\n');res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="rekap-misi-uang.csv"'});res.end(csv);return}
  return json(res,200,{rows,stats:{students:rows.length,played:rows.filter(r=>r.plays>0).length,best:Math.max(0,...rows.map(r=>r.bestScore||0))}})}
 return fail(res,404,'Layanan tidak ditemukan.');
 }catch(e){if(e.message==='Permintaan terlalu besar.'||e.message==='Data tidak valid.')return fail(res,400,e.message);console.error(e);return fail(res,500,'Terjadi kesalahan pada server.')}});
const port=Number(process.env.PORT||3000);server.listen(port,process.env.HOST||'0.0.0.0',()=>{console.log(`Misi Uang siap di http://localhost:${port}`);for(const group of Object.values(networkInterfaces()))for(const net of group||[])if(net.family==='IPv4'&&!net.internal)console.log(`Alamat untuk siswa di Wi-Fi yang sama: http://${net.address}:${port}`)});
