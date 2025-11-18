Passos para configurar Login com Google (Genius Hub)

1) Criar credenciais no Google Cloud Console
- Acesse https://console.cloud.google.com/apis/credentials
- Crie um OAuth 2.0 Client ID (Application type: Web application)
- Em "Authorized redirect URIs" adicione:
  - http://localhost:3001/api/auth/google/callback
- Anote o CLIENT_ID e CLIENT_SECRET.

2) Definir variáveis de ambiente no Windows (PowerShell)
- Para sessão atual:
```powershell
$env:GOOGLE_CLIENT_ID = 'SEU_CLIENT_ID'
$env:GOOGLE_CLIENT_SECRET = 'SEU_CLIENT_SECRET'
# Opcional: abrir servidor
node .\server.js
```
- Para definir permanentemente, use as Configurações do Windows > Variáveis de Ambiente.

3) Reiniciar o servidor Node
- Se o servidor já estiver rodando, reinicie para carregar as variáveis.

4) Testar
- Abra `teladelogin.html` no navegador e clique em "Entrar com Google".
- Se tudo estiver configurado, você será redirecionado ao Google e, após aceitar, o backend retornará uma página que grava o token e leva para `/index.html`.

Observações de CORS e Cookies
- O backend define um cookie HttpOnly `gh_token` para autenticação.
- Para que o cookie funcione em requisições cross-origin, carregue o frontend a partir de `http://localhost:3001` ou ajuste seu servidor de frontend para usar a mesma origem.
- Em desenvolvimento, mantivemos o token também no JSON de resposta para compatibilidade com `localStorage`.

Se quiser, eu posso gerar um pequeno script PowerShell para automatizar a criação do processo de inicialização com as variáveis definidas temporariamente.