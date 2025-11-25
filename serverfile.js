const http = require('http')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'
const DB_FILE = path.join(__dirname, 'db.json')
const UPLOAD_DIR = path.join(__dirname, 'uploads')

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true })
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], challenges: [], submissions: [], notifications: [], messages: [] }, null, 2))

function readDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'))
}
function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2))
}

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}
function signJWT(payload, secret, options = {}) {
  const header = { alg: 'HS256', typ: 'JWT' }
  const exp = options.expiresIn ? (Math.floor(Date.now()/1000) + (typeof options.expiresIn==='number'?options.expiresIn:7*24*3600)) : undefined
  const body = { ...payload, ...(exp?{exp}: {}) }
  const h = base64url(JSON.stringify(header))
  const p = base64url(JSON.stringify(body))
  const data = h + '.' + p
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')
  return data + '.' + sig
}
function verifyJWT(token, secret) {
  const [h, p, s] = token.split('.')
  if (!h || !p || !s) throw new Error('bad_token')
  const data = h + '.' + p
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')
  if (sig !== s) throw new Error('bad_sig')
  const payload = JSON.parse(Buffer.from(p.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8'))
  if (payload.exp && Math.floor(Date.now()/1000) > payload.exp) throw new Error('expired')
  return payload
}
function hashPassword(p) {
  const salt = crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(p, salt, 100000, 32, 'sha256').toString('hex')
  return salt + ':' + hash
}
function checkPassword(p, stored) {
  const [salt, hash] = stored.split(':')
  const calc = crypto.pbkdf2Sync(p, salt, 100000, 32, 'sha256').toString('hex')
  return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(calc,'hex'))
}
function uuid() { return crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(36)+Math.random().toString(36).slice(2)) }

function send(res, status, data, headers={}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data)
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', ...headers })
  res.end(body)
}
function parseBody(req) {
  return new Promise((resolve) => {
    let data=''
    req.on('data', chunk => { data += chunk })
    req.on('end', () => {
      const ct = req.headers['content-type'] || ''
      if (ct.includes('application/json')) {
        try { resolve(JSON.parse(data||'{}')) } catch { resolve({}) }
      } else { resolve({ raw: data }) }
    })
  })
}
function getAuthUser(req) {
  const h = req.headers['authorization'] || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : null
  if (!token) return null
  try {
    const payload = verifyJWT(token, JWT_SECRET)
    const db = readDB()
    return db.users.find(u => u.id === payload.sub) || null
  } catch { return null }
}

const server = http.createServer(async (req, res) => {
  const init = readDB()
  if (init.users.length === 0) {
    init.users.push({ id: 'u-admin', email: 'admin@genius.local', passwordHash: hashPassword('admin123'), role: 'admin', name: 'Admin', institution: 'Genius', bio: '', avatar: '', points: 0, achievements: [] })
    writeDB(init)
  }
  if (req.method === 'OPTIONS') return send(res, 200, '')
  if (req.url.startsWith('/uploads/')) {
    const filePath = path.join(UPLOAD_DIR, req.url.replace('/uploads/',''))
    if (fs.existsSync(filePath)) {
      const stream = fs.createReadStream(filePath)
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Access-Control-Allow-Origin': '*' })
      return stream.pipe(res)
    } else return send(res, 404, { error: 'not_found' })
  }
  if (req.url === '/health') return send(res, 200, { ok: true })

  const url = new URL(req.url, 'http://localhost')
  const db = readDB()
  const user = getAuthUser(req)

  if (req.method === 'POST' && url.pathname === '/api/auth/register') {
    const body = await parseBody(req)
    const { email, password, role = 'aluno', name = '', institution = '' } = body
    if (!email || !password) return send(res, 400, { error: 'missing_fields' })
    if (db.users.find(u => u.email === email)) return send(res, 409, { error: 'email_exists' })
    const hash = hashPassword(password)
    const u = { id: uuid(), email, passwordHash: hash, role, name, institution, bio: '', avatar: '', points: 0, achievements: [] }
    db.users.push(u); writeDB(db)
    const token = signJWT({ sub: u.id, role: u.role }, JWT_SECRET, { expiresIn: 7*24*3600 })
    return send(res, 200, { token, user: { id: u.id, email, role, name, institution } })
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/login') {
    const body = await parseBody(req)
    const { email, password } = body
    const u = db.users.find(x => x.email === email)
    if (!u) return send(res, 404, { error: 'user_not_found' })
    if (!checkPassword(password||'', u.passwordHash)) return send(res, 401, { error: 'invalid_credentials' })
    const token = signJWT({ sub: u.id, role: u.role }, JWT_SECRET, { expiresIn: 7*24*3600 })
    return send(res, 200, { token, user: { id: u.id, email: u.email, role: u.role, name: u.name, institution: u.institution } })
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/recover') {
    const body = await parseBody(req)
    const { email, newPassword } = body
    const u = db.users.find(x => x.email === email)
    if (!u) return send(res, 404, { error: 'user_not_found' })
    u.passwordHash = hashPassword(newPassword||'')
    writeDB(db)
    return send(res, 200, { ok: true })
  }

  if (req.method === 'GET' && url.pathname === '/api/users/me') {
    if (!user) return send(res, 401, { error: 'missing_token' })
    const { id, email, role, name, institution, bio, avatar, points, achievements } = user
    return send(res, 200, { id, email, role, name, institution, bio, avatar, points, achievements })
  }

  if (req.method === 'PUT' && url.pathname === '/api/users/me') {
    if (!user) return send(res, 401, { error: 'missing_token' })
    const body = await parseBody(req)
    const u = db.users.find(x => x.id === user.id)
    if (!u) return send(res, 404, { error: 'user_not_found' })
    ;['name','institution','bio','avatar'].forEach(k => { if (body[k] !== undefined) u[k] = body[k] })
    writeDB(db)
    return send(res, 200, { ok: true })
  }

  if (req.method === 'POST' && url.pathname === '/api/challenges') {
    if (!user || !['empresa','admin'].includes(user.role)) return send(res, 403, { error: 'forbidden' })
    const body = await parseBody(req)
    const { title, description, category, featured = false } = body
    if (!title || !description || !category) return send(res, 400, { error: 'missing_fields' })
    const c = { id: uuid(), title, description, category, featured, companyId: user.id, createdAt: Date.now(), status: 'open' }
    db.challenges.push(c); writeDB(db)
    return send(res, 200, c)
  }

  if (req.method === 'GET' && url.pathname === '/api/challenges') {
    const q = url.searchParams.get('q') || ''
    const category = url.searchParams.get('category') || ''
    const featured = url.searchParams.get('featured')
    let arr = db.challenges
    if (q) arr = arr.filter(c => c.title.toLowerCase().includes(String(q).toLowerCase()))
    if (category) arr = arr.filter(c => c.category === category)
    if (featured !== null && featured !== undefined) arr = arr.filter(c => !!c.featured === (featured === 'true'))
    return send(res, 200, arr)
  }

  if (req.method === 'GET' && url.pathname.startsWith('/api/challenges/')) {
    const parts = url.pathname.split('/')
    const id = parts[3]
    if (parts[4] === 'submissions') {
      if (!user || !['empresa','admin'].includes(user.role)) return send(res, 403, { error: 'forbidden' })
      const list = db.submissions.filter(s => s.challengeId === id)
      return send(res, 200, list)
    }
    const c = db.challenges.find(x => x.id === id)
    if (!c) return send(res, 404, { error: 'challenge_not_found' })
    return send(res, 200, c)
  }

  if (req.method === 'POST' && url.pathname.match(/^\/api\/challenges\/[^/]+\/submit$/)) {
    if (!user || user.role !== 'aluno') return send(res, 403, { error: 'forbidden' })
    const id = url.pathname.split('/')[3]
    const c = db.challenges.find(x => x.id === id)
    if (!c) return send(res, 404, { error: 'challenge_not_found' })
    const body = await parseBody(req)
    const files = []
    if (Array.isArray(body.attachments)) {
      body.attachments.forEach(a => {
        try {
          const fn = Date.now() + '-' + (a.name || 'file')
          const b64 = String(a.dataUrl||'').split(',')[1]
          if (b64) fs.writeFileSync(path.join(UPLOAD_DIR, fn), Buffer.from(b64, 'base64'))
          files.push({ name: a.name, path: '/uploads/' + fn })
        } catch {}
      })
    }
    const s = { id: uuid(), challengeId: c.id, studentId: user.id, files, createdAt: Date.now(), status: 'enviado', evaluation: null }
    db.submissions.push(s)
    db.notifications.push({ id: uuid(), userId: c.companyId, message: 'Nova submissão recebida', ts: Date.now(), read: false })
    writeDB(db)
    return send(res, 200, s)
  }

  if (req.method === 'POST' && url.pathname.startsWith('/api/submissions/')) {
    if (!user || !['empresa','admin'].includes(user.role)) return send(res, 403, { error: 'forbidden' })
    const id = url.pathname.split('/')[3]
    if (!url.pathname.endsWith('/evaluate')) return send(res, 404, { error: 'not_found' })
    const body = await parseBody(req)
    const s = db.submissions.find(x => x.id === id)
    if (!s) return send(res, 404, { error: 'submission_not_found' })
    s.status = 'avaliado'
    s.evaluation = { approved: !!body.approved, feedback: body.feedback || '', evaluatorId: user.id }
    const st = db.users.find(u => u.id === s.studentId)
    if (st) {
      st.points = (st.points || 0) + (body.approved ? 100 : 10)
      st.achievements = st.achievements || []
      if (st.points >= 100 && !st.achievements.includes('Primeira Entrega')) st.achievements.push('Primeira Entrega')
      if (st.points >= 500 && !st.achievements.includes('Colaborador')) st.achievements.push('Colaborador')
      db.notifications.push({ id: uuid(), userId: st.id, message: body.approved ? 'Sua submissão foi aprovada' : 'Sua submissão foi avaliada', ts: Date.now(), read: false })
    }
    writeDB(db)
    return send(res, 200, { ok: true })
  }

  if (req.method === 'GET' && url.pathname === '/api/ranking') {
    const arr = db.users.filter(u => u.role === 'aluno').sort((a, b) => (b.points || 0) - (a.points || 0)).slice(0, 50)
    return send(res, 200, arr.map(u => ({ id: u.id, name: u.name, points: u.points || 0 })))
  }

  if (req.method === 'GET' && url.pathname === '/api/notifications') {
    if (!user) return send(res, 401, { error: 'missing_token' })
    const list = db.notifications.filter(n => n.userId === user.id)
    return send(res, 200, list)
  }

  if (req.method === 'POST' && url.pathname === '/api/messages') {
    if (!user) return send(res, 401, { error: 'missing_token' })
    const body = await parseBody(req)
    const { toId, body: text } = body
    if (!toId || !text) return send(res, 400, { error: 'missing_fields' })
    const m = { id: uuid(), fromId: user.id, toId, body: text, ts: Date.now() }
    db.messages.push(m); writeDB(db)
    return send(res, 200, m)
  }

  if (req.method === 'GET' && url.pathname === '/api/messages') {
    if (!user) return send(res, 401, { error: 'missing_token' })
    const withId = url.searchParams.get('with')
    const list = db.messages.filter(m => (m.fromId === user.id && (!withId || m.toId === withId)) || (m.toId === user.id && (!withId || m.fromId === withId)))
    return send(res, 200, list)
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/users') {
    if (!user || user.role !== 'admin') return send(res, 403, { error: 'forbidden' })
    return send(res, 200, db.users.map(u => ({ id: u.id, email: u.email, role: u.role })))
  }

  if (req.method === 'PUT' && url.pathname.startsWith('/api/admin/users/')) {
    if (!user || user.role !== 'admin') return send(res, 403, { error: 'forbidden' })
    const id = url.pathname.split('/')[4]
    const body = await parseBody(req)
    const u = db.users.find(x => x.id === id)
    if (!u) return send(res, 404, { error: 'user_not_found' })
    u.role = body.role || u.role
    writeDB(db)
    return send(res, 200, { ok: true })
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/challenges') {
    if (!user || user.role !== 'admin') return send(res, 403, { error: 'forbidden' })
    return send(res, 200, db.challenges)
  }

  if (req.method === 'PUT' && url.pathname.startsWith('/api/admin/challenges/') && url.pathname.endsWith('/status')) {
    if (!user || user.role !== 'admin') return send(res, 403, { error: 'forbidden' })
    const id = url.pathname.split('/')[4]
    const body = await parseBody(req)
    const c = db.challenges.find(x => x.id === id)
    if (!c) return send(res, 404, { error: 'challenge_not_found' })
    c.status = body.status || c.status
    writeDB(db)
    return send(res, 200, { ok: true })
  }

  if (req.method === 'DELETE' && url.pathname.startsWith('/api/admin/challenges/')) {
    if (!user || user.role !== 'admin') return send(res, 403, { error: 'forbidden' })
    const id = url.pathname.split('/')[4]
    db.challenges = db.challenges.filter(c => c.id !== id)
    writeDB(db)
    return send(res, 200, { ok: true })
  }

  return send(res, 404, { error: 'not_found' })
})

server.listen(PORT, () => {
  console.log('Genius Hub API running on http://localhost:' + PORT)
})