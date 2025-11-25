const http = require('http')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const PORT = 3001
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'
const DB_FILE = path.join(__dirname, 'db.json')
const UPLOAD_DIR = path.join(__dirname, 'uploads')

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true })
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], challenges: [], submissions: [], notifications: [], messages: [], projects: [], project_files: [], project_comments: [] }, null, 2))

function readDB() {
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'))
  db.projects = db.projects || []
  db.project_files = db.project_files || []
  db.project_comments = db.project_comments || []
  db.conversations = db.conversations || []
  db.users = db.users || []
  db.challenges = db.challenges || []
  db.submissions = db.submissions || []
  db.notifications = db.notifications || []
  db.messages = db.messages || []
  return db
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

function sanitizeCNPJ(input) {
  if (!input) return ''
  return String(input).replace(/[^0-9]/g, '')
}

function validateCNPJ(cnpj) {
  cnpj = sanitizeCNPJ(cnpj)
  if (!cnpj || cnpj.length !== 14) return false
  // reject known invalid sequences
  if (/^(\d)\1+$/.test(cnpj)) return false
  const calcDigit = (cnpj, pos) => {
    const nums = cnpj.slice(0, pos).split('').map(Number)
    let factor = pos - 7
    let sum = 0
    for (let i = nums.length - 1; i >= 0; i--) {
      sum += nums[i] * factor
      factor = factor === 2 ? 9 : factor - 1
    }
    const res = sum % 11
    return res < 2 ? 0 : 11 - res
  }
  const d1 = calcDigit(cnpj, 12)
  const d2 = calcDigit(cnpj, 13)
  return Number(cnpj[12]) === d1 && Number(cnpj[13]) === d2
}

function send(res, status, data, headers={}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data)
  // preserve any CORS headers previously set on the response (so credentialed requests keep the proper origin)
  const corsHeaders = {}
  ;['access-control-allow-origin','access-control-allow-headers','access-control-allow-methods','access-control-allow-credentials'].forEach(h => {
    const v = res.getHeader && res.getHeader(h)
    if (v) corsHeaders[h] = v
  })
  res.writeHead(status, { 'Content-Type': 'application/json', ...(corsHeaders || {}), ...(headers || {}) })
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

// OpenAI project API key helper: try environment key, else try to list/create keys using admin key
let _cached_openai_key = { key: null, expires: 0 }
async function getProjectOpenAIKey() {
  if (process.env.OPENAI_API_KEY) return process.env.OPENAI_API_KEY
  if (Date.now() < _cached_openai_key.expires && _cached_openai_key.key) return _cached_openai_key.key
  const admin = process.env.OPENAI_ADMIN_KEY
  const proj = process.env.OPENAI_PROJECT_ID
  if (!admin || !proj) return null
  try {
    // try list keys
    const listResp = await fetch(`https://api.openai.com/v1/organization/projects/${proj}/api_keys?limit=20`, { headers: { Authorization: 'Bearer ' + admin } })
    const lj = await listResp.json().catch(()=>null)
    if (lj && Array.isArray(lj.data)) {
      // try to find an entry that exposes a secret (some APIs return secret only on create)
      for (const k of lj.data) {
        if (k && (k.secret || k.key || k.value)) {
          _cached_openai_key.key = k.secret || k.key || k.value
          _cached_openai_key.expires = Date.now() + 5*60*1000
          return _cached_openai_key.key
        }
      }
    }
    // if no secret available, attempt to create a new key for the project
    try {
      const createResp = await fetch(`https://api.openai.com/v1/organization/projects/${proj}/api_keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + admin },
        body: JSON.stringify({ name: 'genius-hub-temp-' + Date.now() })
      })
      const cj = await createResp.json().catch(()=>null)
      if (cj && (cj.secret || cj.key || cj.value)) {
        _cached_openai_key.key = cj.secret || cj.key || cj.value
        _cached_openai_key.expires = Date.now() + 5*60*1000
        return _cached_openai_key.key
      }
    } catch (e) {
      // ignore create errors
    }
  } catch (e) {
    // ignore
  }
  return null
}

const server = http.createServer(async (req, res) => {
  const init = readDB()
  // CORS handling per-request: echo Origin when present so cookies/credentials work
  const origin = req.headers['origin'] || req.headers['referer'] || ''
  if (origin) {
    // when credentials are used, Access-Control-Allow-Origin must be the specific origin
    res.setHeader('Access-Control-Allow-Origin', origin)
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  if (init.users.length === 0) {
    init.users.push({ id: 'u-admin', email: 'admin@genius.local', passwordHash: hashPassword('admin123'), role: 'admin', name: 'Admin', institution: 'Genius', bio: '', avatar: '', points: 0, achievements: [] })
    writeDB(init)
  }
  const db0 = readDB()
  if (db0.projects.length === 0) {
    const pid = 'p-default'
    db0.projects.push({ id: pid, name: 'Projeto Demo', ownerId: 'u-admin', createdAt: Date.now() })
    db0.project_files.push({ id: uuid(), projectId: pid, name: 'Briefing.pdf', version: 2, path: '', createdAt: Date.now() })
    db0.project_files.push({ id: uuid(), projectId: pid, name: 'prototipo.fig', version: 5, path: '', createdAt: Date.now() })
    writeDB(db0)
  }
  if (req.method === 'OPTIONS') {
    // Preflight response - echo allowed origin and headers
    res.writeHead(200, { 'Content-Type': 'application/json' })
    return res.end('')
  }
  if (req.url.startsWith('/uploads/')) {
    const filePath = path.join(UPLOAD_DIR, req.url.replace('/uploads/',''))
    if (fs.existsSync(filePath)) {
      const stream = fs.createReadStream(filePath)
      // echo origin if present (do not use wildcard when credentials are enabled)
      const hdrs = { 'Content-Type': 'application/octet-stream' }
      const curOrigin = req.headers['origin'] || req.headers['referer'] || ''
      if (curOrigin) hdrs['Access-Control-Allow-Origin'] = curOrigin
      return stream.pipe(res.writeHead(200, hdrs) || res)
    } else return send(res, 404, { error: 'not_found' })
  }
  if (req.url === '/health') return send(res, 200, { ok: true })

  const url = new URL(req.url, 'http://localhost')
  const db = readDB()
  const user = getAuthUser(req)

  if (req.method === 'POST' && url.pathname === '/api/auth/register') {
    const body = await parseBody(req)
    const { email, password, role = 'aluno', name = '', institution = '', company = '', cnpj = '', contact = '' } = body
    if (!email || !password) return send(res, 400, { error: 'missing_fields' })
    if (db.users.find(u => u.email === email)) return send(res, 409, { error: 'email_exists' })
    const hash = hashPassword(password)
    // include company-specific fields when role is empresa
    const u = { id: uuid(), email, passwordHash: hash, role, name, institution, bio: '', avatar: '', points: 0, achievements: [], createdAt: Date.now() }
    if (role === 'empresa') {
      const clean = sanitizeCNPJ(cnpj || '')
      if (!validateCNPJ(clean)) return send(res, 400, { error: 'invalid_cnpj' })
      u.company = company || ''
      u.cnpj = clean
      u.contact = contact || ''
    }
    db.users.push(u); writeDB(db)
    const token = signJWT({ sub: u.id, role: u.role }, JWT_SECRET, { expiresIn: 7*24*3600 })
    const maxAge = 7*24*3600
    const userResp = { id: u.id, email, role, name: u.name, institution: u.institution }
    if (role === 'empresa') { userResp.company = u.company; userResp.cnpj = u.cnpj; userResp.contact = u.contact }
    return send(res, 200, { token, user: userResp }, { 'Set-Cookie': `gh_token=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax` })
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/login') {
    const body = await parseBody(req)
    const { email, password } = body
    const u = db.users.find(x => x.email === email)
    if (!u) return send(res, 404, { error: 'user_not_found' })
    if (!checkPassword(password||'', u.passwordHash)) return send(res, 401, { error: 'invalid_credentials' })
    const token = signJWT({ sub: u.id, role: u.role }, JWT_SECRET, { expiresIn: 7*24*3600 })
    const maxAge = 7*24*3600
    const userResp = { id: u.id, email: u.email, role: u.role, name: u.name, institution: u.institution }
    if (u.role === 'empresa') { userResp.company = u.company || ''; userResp.cnpj = u.cnpj || ''; userResp.contact = u.contact || '' }
    return send(res, 200, { token, user: userResp }, { 'Set-Cookie': `gh_token=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax` })
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
    const { id, email, role, name, institution, bio, avatar, points, achievements, company, cnpj, contact } = user
    const resp = { id, email, role, name, institution, bio, avatar, points, achievements }
    if (role === 'empresa') { resp.company = company || ''; resp.cnpj = cnpj || ''; resp.contact = contact || '' }
    return send(res, 200, resp)
  }

  // Admin: list registered companies
  if (req.method === 'GET' && url.pathname === '/api/admin/companies') {
    if (!user || user.role !== 'admin') return send(res, 403, { error: 'forbidden' })
    const companies = db.users.filter(u => u.role === 'empresa').map(u => ({ id: u.id, email: u.email, company: u.company || '', cnpj: u.cnpj || '', contact: u.contact || '', createdAt: u.createdAt || null }))
    return send(res, 200, companies)
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
    if (!user || user.role !== 'empresa') return send(res, 403, { error: 'forbidden' })
    const body = await parseBody(req)
    const { title, description, category, featured = false } = body
    if (!title || !description || !category) return send(res, 400, { error: 'missing_fields' })
    const c = { id: uuid(), title, description, category, featured, companyId: user.id, createdAt: Date.now(), status: 'open' }
    db.challenges.push(c);
    const students = db.users.filter(u => u.role === 'aluno')
    students.forEach(s => db.notifications.push({ id: uuid(), userId: s.id, message: 'Novo desafio: '+title, ts: Date.now(), read: false }))
    writeDB(db)
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

  // AI assistant endpoint: accepts { prompt, projectId }
  if (req.method === 'POST' && url.pathname === '/api/assistant') {
    const body = await parseBody(req)
    const prompt = String(body.prompt || '')
    const projectId = body.projectId || null
    const projectFiles = (db.project_files || []).filter(f => !projectId || f.projectId === projectId)
    const projectComments = (db.project_comments || []).filter(c => !projectId || c.projectId === projectId)

    // Try to obtain an OpenAI key (env OPENAI_API_KEY or via org admin key / project)
    const openaiKey = await getProjectOpenAIKey()
    if (openaiKey) {
      try {
        const messages = [
          { role: 'system', content: 'Você é um assistente que responde de forma clara e curta, fornecendo sugestões úteis sobre projetos e arquivos.' },
          { role: 'user', content: `Contexto - arquivos: ${projectFiles.map(f=>f.name+' v'+f.version).join(', ')}; comentários: ${projectComments.map(c=>c.text).slice(-5).join(' | ')}` },
          { role: 'user', content: prompt }
        ]
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + openaiKey },
          body: JSON.stringify({ model: 'gpt-3.5-turbo', messages, max_tokens: 300 })
        })
        const j = await resp.json()
        const ans = j.choices && j.choices[0] && j.choices[0].message ? j.choices[0].message.content : (j.error && j.error.message) || JSON.stringify(j)
        return send(res, 200, { answer: ans })
      } catch (e) {
        return send(res, 500, { error: 'ai_error', message: String(e) })
      }
    }

    // Store message in conversation history (if user present)
    try {
      if (user) {
        const conv = db.conversations.find(c => c.userId === user.id) || { userId: user.id, messages: [] }
        conv.messages = conv.messages || []
        conv.messages.push({ role: 'user', content: prompt, ts: Date.now() })
        // keep last 40 messages
        conv.messages = conv.messages.slice(-40)
        const idx = db.conversations.findIndex(c => c.userId === user.id)
        if (idx === -1) {
          db.conversations.push(conv)
        } else {
          db.conversations[idx] = conv
        }
        writeDB(db)
      }
    } catch (e) {}

    // Fallback simple assistant (no external API)
    const suggestions = []
    if (prompt.toLowerCase().includes('vers')) suggestions.push('Verifique as versões dos arquivos no projeto: ' + projectFiles.map(f=>f.name+' v'+f.version).join(', '))
    if (prompt.toLowerCase().includes('upload')) suggestions.push('Para enviar arquivos, use o botão de upload na seção Projetos.')
    if (!suggestions.length) suggestions.push('Resumo do projeto: arquivos - ' + (projectFiles.length || 0) + '; comentários recentes - ' + (projectComments.slice(-3).map(c=>c.text).join(' | ') || 'nenhum'))
    const answerText = suggestions.join(' | ')
    try {
      if (user) {
        const conv = db.conversations.find(c => c.userId === user.id) || { userId: user.id, messages: [] }
        conv.messages = conv.messages || []
        conv.messages.push({ role: 'assistant', content: answerText, ts: Date.now() })
        conv.messages = conv.messages.slice(-40)
        const idx = db.conversations.findIndex(c => c.userId === user.id)
        if (idx === -1) {
          db.conversations.push(conv)
        } else {
          db.conversations[idx] = conv
        }
        writeDB(db)
      }
    } catch (e) {}
    return send(res, 200, { answer: answerText })
  }

  // Streaming assistant: proxies OpenAI streaming API and relays tokens to the client
  if (req.method === 'POST' && url.pathname === '/api/assistant/stream') {
    const body = await parseBody(req)
    const prompt = String((body && body.prompt) || '')
    const projectId = body.projectId || null
    const projectFiles = (db.project_files || []).filter(f => !projectId || f.projectId === projectId)
    const projectComments = (db.project_comments || []).filter(c => !projectId || c.projectId === projectId)
    const openaiKey = await getProjectOpenAIKey()
    if (!openaiKey) return send(res, 400, { error: 'openai_not_configured' })

    // build messages with history
    const messages = [{ role: 'system', content: 'Você é um assistente que responde de forma clara e curta, fornecendo sugestões úteis sobre projetos e arquivos.' }]
    if (user) {
      const conv = db.conversations.find(c => c.userId === user.id)
      if (conv && Array.isArray(conv.messages)) {
        conv.messages.slice(-20).forEach(m => messages.push({ role: m.role, content: m.content }))
      }
    }
    messages.push({ role: 'user', content: `Contexto - arquivos: ${projectFiles.map(f=>f.name+' v'+f.version).join(', ')}; comentários: ${projectComments.map(c=>c.text).slice(-5).join(' | ')}` })
    messages.push({ role: 'user', content: prompt })

    // persist user message
    try {
      if (user) {
        const conv = db.conversations.find(c => c.userId === user.id) || { userId: user.id, messages: [] }
        conv.messages = conv.messages || []
        conv.messages.push({ role: 'user', content: prompt, ts: Date.now() })
        conv.messages = conv.messages.slice(-40)
        const idx = db.conversations.findIndex(c => c.userId === user.id)
        if (idx === -1) {
          db.conversations.push(conv)
        } else {
          db.conversations[idx] = conv
        }
        writeDB(db)
      }
    } catch (e) {}

    // Proxy stream
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' })
    try {
      const oa = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + openaiKey },
        body: JSON.stringify({ model: 'gpt-3.5-turbo', messages, max_tokens: 600, stream: true })
      })
      const reader = oa.body.getReader()
      const dec = new TextDecoder()
      let done = false
      let assistantText = ''
      while (!done) {
        const { value, done: d } = await reader.read()
        done = d
        if (value) {
          const chunk = dec.decode(value)
          // OpenAI stream uses lines starting with 'data: '
          const parts = chunk.split('\n')
          parts.forEach(p => {
            if (!p) return
            if (p.indexOf('data: ') === 0) {
              const data = p.slice(6).trim()
              if (data === '[DONE]') {
                // finish
              } else {
                try {
                  const j = JSON.parse(data)
                  const delta = j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content
                  if (delta) {
                    assistantText += delta
                    res.write(`data: ${JSON.stringify({ delta })}\n\n`)
                  }
                } catch (e) {
                  // ignore parse
                }
              }
            }
          })
        }
      }
      res.write(`data: ${JSON.stringify({ done: true })}\n\n`)
      // Save assistant message to conversation (full reconstructed text)
      try {
        if (user) {
          const conv = db.conversations.find(c => c.userId === user.id) || { userId: user.id, messages: [] }
          conv.messages = conv.messages || []
          conv.messages.push({ role: 'assistant', content: assistantText, ts: Date.now() })
          conv.messages = conv.messages.slice(-40)
          const idx = db.conversations.findIndex(c => c.userId === user.id)
          if (idx === -1) {
            db.conversations.push(conv)
          } else {
            db.conversations[idx] = conv
          }
          writeDB(db)
        }
      } catch (e) {}
      return res.end()
    } catch (e) {
      return send(res, 500, { error: 'stream_error', message: String(e) })
    }
  }

  // Google OAuth endpoints (require GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars)
  if (req.method === 'GET' && url.pathname === '/api/auth/google') {
    const clientId = process.env.GOOGLE_CLIENT_ID
    const redirect = `http://localhost:${PORT}/api/auth/google/callback`
    if (!clientId) {
      // Friendly HTML response explaining configuration steps
      const html = `<!doctype html><html><body style="font-family:Arial,sans-serif;padding:20px"><h2>Google OAuth não configurado</h2><p>Para habilitar o Login com Google, defina as variáveis de ambiente <code>GOOGLE_CLIENT_ID</code> e <code>GOOGLE_CLIENT_SECRET</code> no servidor e registre o redirect URI:</p><pre>http://localhost:${PORT}/api/auth/google/callback</pre><p>Depois reinicie o servidor.</p></body></html>`
      res.writeHead(200, { 'Content-Type': 'text/html' })
      return res.end(html)
    }
    const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth' +
      `?client_id=${encodeURIComponent(clientId)}&response_type=code&scope=${encodeURIComponent('openid email profile')}&redirect_uri=${encodeURIComponent(redirect)}&access_type=online&prompt=select_account`
    res.writeHead(302, { Location: authUrl })
    return res.end()
  }

  if (req.method === 'GET' && url.pathname === '/api/auth/google/callback') {
    const code = url.searchParams.get('code')
    const clientId = process.env.GOOGLE_CLIENT_ID
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET
    const redirect = `http://localhost:${PORT}/api/auth/google/callback`
    if (!clientId || !clientSecret) {
      const html = `<!doctype html><html><body style="font-family:Arial,sans-serif;padding:20px"><h2>Google OAuth não configurado</h2><p>Faltam as variáveis de ambiente <code>GOOGLE_CLIENT_ID</code> e/ou <code>GOOGLE_CLIENT_SECRET</code>. Defina-as e reinicie o servidor.</p></body></html>`
      res.writeHead(200, { 'Content-Type': 'text/html' })
      return res.end(html)
    }
    if (!code) return send(res, 400, { error: 'missing_code' })
    try {
      const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirect, grant_type: 'authorization_code' })
      })
      const tokenJson = await tokenResp.json()
      if (!tokenJson.access_token) return send(res, 400, { error: 'token_failed', detail: tokenJson })
      const userInfoResp = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: 'Bearer ' + tokenJson.access_token } })
      const userInfo = await userInfoResp.json()
      const email = userInfo.email
      if (!email) return send(res, 400, { error: 'no_email' })
      // find or create user
      let u = db.users.find(x => x.email === email)
      if (!u) {
        u = { id: uuid(), email, passwordHash: hashPassword(uuid().slice(0,8)), role: 'aluno', name: userInfo.name || '', institution: '' }
        db.users.push(u); writeDB(db)
      }
      const token = signJWT({ sub: u.id, role: u.role }, JWT_SECRET, { expiresIn: 7*24*3600 })
      const maxAge = 7*24*3600
      // respond with small HTML that stores token in localStorage (fallback) and redirects to /index.html
      const html = `<!doctype html><html><body><script>try{localStorage.setItem('gh_token', ${JSON.stringify(token)})}catch(e){};window.location.href='/index.html';</script></body></html>`
      res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': `gh_token=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax` })
      return res.end(html)
    } catch (e) {
      return send(res, 500, { error: 'google_error', message: String(e) })
    }
  }

  // Projects routes
  if (req.method === 'GET' && url.pathname === '/api/projects') {
    return send(res, 200, db.projects || [])
  }

  if (req.method === 'POST' && url.pathname === '/api/projects') {
    if (!user) return send(res, 401, { error: 'missing_token' })
    const body = await parseBody(req)
    const p = { id: uuid(), name: body.name || 'Projeto', ownerId: user.id, createdAt: Date.now() }
    db.projects.push(p); writeDB(db)
    return send(res, 200, p)
  }

  if (req.method === 'GET' && url.pathname.startsWith('/api/projects/')) {
    const parts = url.pathname.split('/')
    const pid = parts[3]
    if (parts[4] === 'files') {
      const list = (db.project_files || []).filter(f => f.projectId === pid).sort((a,b)=>a.name.localeCompare(b.name))
      return send(res, 200, list)
    }
    if (parts[4] === 'comments') {
      const list = (db.project_comments || []).filter(c => c.projectId === pid).sort((a,b)=>a.ts-b.ts)
      return send(res, 200, list)
    }
    const p = db.projects.find(x => x.id === pid)
    if (!p) return send(res, 404, { error: 'project_not_found' })
    return send(res, 200, p)
  }

  if (req.method === 'POST' && url.pathname.match(/^\/api\/projects\/[^/]+\/files$/)) {
    if (!user) return send(res, 401, { error: 'missing_token' })
    const pid = url.pathname.split('/')[3]
    const body = await parseBody(req)
    const atts = Array.isArray(body.attachments) ? body.attachments : []
    const created = []
    atts.forEach(a => {
      try {
        const fn = Date.now() + '-' + (a.name || 'file')
        const b64 = String(a.dataUrl||'').split(',')[1]
        let fp = ''
        if (b64) {
          fs.writeFileSync(path.join(UPLOAD_DIR, fn), Buffer.from(b64, 'base64'))
          fp = '/uploads/'+fn
        }
        const existing = (db.project_files||[]).filter(f => f.projectId === pid && f.name === a.name)
        const ver = existing.length ? Math.max(...existing.map(f=>f.version))+1 : 1
        const rec = { id: uuid(), projectId: pid, name: a.name, version: ver, path: fp, createdAt: Date.now(), authorId: user.id }
        db.project_files.push(rec)
        created.push(rec)
      } catch {}
    })
    writeDB(db)
    return send(res, 200, created)
  }

  if (req.method === 'POST' && url.pathname.match(/^\/api\/projects\/[^/]+\/comments$/)) {
    if (!user) return send(res, 401, { error: 'missing_token' })
    const pid = url.pathname.split('/')[3]
    const body = await parseBody(req)
    const c = { id: uuid(), projectId: pid, userId: user.id, text: body.text || '', ts: Date.now() }
    db.project_comments.push(c); writeDB(db)
    return send(res, 200, c)
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
 