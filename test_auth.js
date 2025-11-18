(async () => {
  const base = 'http://localhost:3001'
  const email = `test${Date.now()}@local`
  const password = 'senha123'

  function log(tag, status, body) {
    console.log('---', tag, 'status=' + status)
    console.log(body)
  }

  async function safeJson(res) {
    try { return await res.json() } catch { return await res.text() }
  }

  try {
    let res = await fetch(base + '/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, role: 'aluno' })
    })
    log('register', res.status, await safeJson(res))

    res = await fetch(base + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
    const loginBody = await safeJson(res)
    log('login', res.status, loginBody)

    if (loginBody && loginBody.token) {
      res = await fetch(base + '/api/users/me', {
        headers: { 'Authorization': 'Bearer ' + loginBody.token }
      })
      log('me', res.status, await safeJson(res))
    }
  } catch (e) {
    console.error('error', e)
    process.exit(1)
  }
})()
