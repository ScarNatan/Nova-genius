Autenticação com cookie HttpOnly (melhor prática)

Resumo
- Em vez de armazenar o token JWT no `localStorage`, é mais seguro enviar o token ao cliente em um cookie `HttpOnly` configurado pelo servidor. Cookies `HttpOnly` não são acessíveis via JavaScript, reduzindo o risco de vazamento via XSS.

O que precisa mudar no backend (Express.js)
1. Ao autenticar (login/register), gere o token (JWT) normalmente.
2. Em vez de retornar o token no corpo da resposta e depender do front-end para armazená-lo,
   envie o token como cookie:

Exemplo (Express + cookie-parser):

```js
const express = require('express')
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())
app.use(cookieParser())

// Configurar CORS para permitir cookies
const cors = require('cors')
app.use(cors({ origin: 'http://localhost:5500', credentials: true }))

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body
  // autenticar usuário e gerar token
  const token = jwt.sign({ sub: 'userId' }, process.env.JWT_SECRET, { expiresIn: '7d' })
  // definir cookie HttpOnly
  res.cookie('gh_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
  })
  return res.json({ ok: true })
})

// Exemplo de rota protegida lendo cookie
app.get('/api/profile', (req, res) => {
  const token = req.cookies.gh_token
  if (!token) return res.status(401).json({ error: 'Não autenticado' })
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET)
    // buscar perfil com payload.sub
    res.json({ userId: payload.sub })
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' })
  }
})

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('gh_token', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax' })
  res.json({ ok: true })
})
```

O que muda no front-end
- Não salve mais o token em `localStorage`.
- Ao chamar o backend, envie `credentials: 'include'` no fetch para que o navegador envie o cookie automaticamente.
- Não setar header `Authorization: Bearer ...` (o servidor já lê o cookie).

Exemplo mínimo de chamada (fetch):

```js
fetch('http://localhost:3000/api/profile', {
  method: 'GET',
  credentials: 'include'
})
```

CORS importante
- O servidor deve habilitar `credentials: true` e permitir a origem do front-end explicitamente. Por exemplo, com o pacote `cors`:

```js
app.use(cors({ origin: 'http://localhost:5500', credentials: true }))
```

Considerações de segurança
- `secure: true` garante envio do cookie apenas via HTTPS. Em desenvolvimento local usando HTTP, configure `secure: false`.
- `sameSite: 'Lax'` ou `Strict` ajuda a mitigar CSRF; para aplicações que precisam de maior proteção contra CSRF, combine com tokens CSRF (double submit cookie) ou use SameSite=Strict quando aplicável.
- Use `maxAge` apropriado e renove token com refresh tokens quando necessário.

Migração gradual
- Você pode suportar ambos (cookie + retorno do token no corpo) temporariamente enquanto atualiza o front-end. Mas o objetivo final é remover armazenamento no `localStorage`.

Resumo rápido de passos para migrar
1. No servidor, setar cookie HttpOnly com o token após login/register.
2. Atualizar CORS para permitir credentials.
3. No cliente, remover leitura/escrita de `localStorage` e usar `fetch(..., { credentials: 'include' })`.
4. Atualizar middleware/rotas do servidor para ler token de `req.cookies`.

Se quiser, posso gerar um exemplo completo de backend (`server-cookie.js`) baseado no seu `server.js` atual; envie o arquivo `server.js` e eu adapto o código para usar cookie HttpOnly.