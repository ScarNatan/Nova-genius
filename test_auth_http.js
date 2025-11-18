const http = require('http')

function req(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: 'localhost', port: 3001, path, method, headers: { 'Content-Type': 'application/json', ...headers } }
    const r = http.request(opts, res => {
      let data = ''
      res.on('data', c => data += c)
      res.on('end', () => {
        const ct = (res.headers['content-type'] || '')
        let parsed = data
        if (ct.includes('application/json')) {
          try { parsed = JSON.parse(data) } catch(e) { parsed = data }
        }
        resolve({ status: res.statusCode, body: parsed, headers: res.headers })
      })
    })
    r.on('error', reject)
    if (body) r.write(JSON.stringify(body))
    r.end()
  })
}

;(async ()=>{
  try {
    const email = `node_test_${Date.now()}@local`
    const password = 'senha123'
    console.log('Trying register...')
    const reg = await req('POST', '/api/auth/register', { email, password, role: 'aluno' })
    console.log('register:', reg.status, reg.body)

    console.log('Trying login...')
    const lg = await req('POST', '/api/auth/login', { email, password })
    console.log('login:', lg.status, lg.body)

    if (lg.body && lg.body.token) {
      console.log('Trying /api/users/me...')
      const me = await req('GET', '/api/users/me', null, { Authorization: 'Bearer ' + lg.body.token })
      console.log('me:', me.status, me.body)
    } else {
      console.error('No token returned from login')
    }
  } catch (e) {
    console.error('Error during tests:', e)
    process.exit(1)
  }
})()
