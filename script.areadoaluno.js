// Projetos colaborativos: carregar projetos, arquivos e comentários (área do aluno)
const API = 'http://localhost:3001'
function token() { return localStorage.getItem('gh_token') || '' }

async function api(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(token() ? { Authorization: 'Bearer ' + token() } : {}) }
    const res = await fetch(API + path, { ...opts, credentials: 'include', headers: { ...headers, ...(opts.headers || {}) } })
    if (!res.ok) {
        const text = await res.text().catch(()=>'')
        throw new Error(text || res.statusText || 'Erro')
    }
    const ct = res.headers.get('content-type') || ''
    return ct.includes('application/json') ? res.json() : res.text()
}

async function loadProjects() {
    try {
        const list = await api('/api/projects')
        const sel = document.getElementById('projectSelect')
        sel.innerHTML = ''
        list.forEach(p => {
            const opt = document.createElement('option')
            opt.value = p.id
            opt.textContent = p.name
            sel.appendChild(opt)
        })
        if (list.length) {
            sel.value = list[0].id
            loadProjectDetails(list[0].id)
        } else {
            document.getElementById('projFileList').innerHTML = '<div class="muted">Nenhum projeto encontrado.</div>'
        }
    } catch (e) {
        console.error('Erro carregando projetos', e)
        const filesEl = document.getElementById('projFileList')
        filesEl.innerHTML = ''
        const errDiv = document.createElement('div')
        errDiv.className = 'muted'
        errDiv.textContent = 'Erro carregando projetos.'
        filesEl.appendChild(errDiv)
        const btnRow = document.createElement('div')
        btnRow.style.marginTop = '8px'
        const retry = document.createElement('button')
        retry.className = 'btn'
        retry.textContent = 'Tentar novamente'
        retry.onclick = () => { filesEl.innerHTML = 'Carregando...'; loadProjects() }
        const fallback = document.createElement('button')
        fallback.style.marginLeft = '8px'
        fallback.className = 'btn'
        fallback.textContent = 'Tentar sem credenciais'
        fallback.onclick = async () => {
            filesEl.innerHTML = 'Tentando sem credenciais...'
            try {
                await loadProjectsFallback()
            } catch (err2) {
                filesEl.innerHTML = '<div class="muted">Falha ao carregar sem credenciais</div>'
            }
        }
        btnRow.appendChild(retry)
        btnRow.appendChild(fallback)
        filesEl.appendChild(btnRow)
    }
}

async function loadProjectsFallback() {
    const sel = document.getElementById('projectSelect')
    const filesEl = document.getElementById('projFileList')
    try {
        const r = await fetch(API + '/api/projects', { credentials: 'omit' })
        if (!r.ok) {
            const t = await r.text().catch(()=>r.statusText)
            throw new Error(t || 'Erro')
        }
        const list = await r.json()
        sel.innerHTML = ''
        list.forEach(p => {
            const opt = document.createElement('option')
            opt.value = p.id
            opt.textContent = p.name
            sel.appendChild(opt)
        })
        if (list.length) {
            sel.value = list[0].id
            loadProjectDetails(list[0].id)
        } else {
            filesEl.innerHTML = '<div class="muted">Nenhum projeto encontrado.</div>'
        }
    } catch (e) {
        console.error('Fallback falhou', e)
        throw e
    }
}

async function loadProjectDetails(projectId) {
    const filesEl = document.getElementById('projFileList')
    const commentsEl = document.getElementById('projComments')
    filesEl.innerHTML = 'Carregando...'
    commentsEl.innerHTML = 'Carregando...'
    try {
        const files = await api(`/api/projects/${projectId}/files`)
        filesEl.innerHTML = ''
        if (!files.length) {
            filesEl.innerHTML = '<div class="muted">Nenhum arquivo</div>'
        } else {
            files.forEach(f => {
                const div = document.createElement('div')
                div.className = 'file'
                div.innerHTML = `<div>${f.name} <div class="sub" style="font-size:12px">v${f.version} • ${new Date(f.createdAt||0).toLocaleString()}</div></div><div>${f.path?`<a href="${f.path}" target="_blank" style="color:#9aa4b2;text-decoration:none">Baixar</a>`:''}</div>`
                filesEl.appendChild(div)
            })
        }
    } catch (e) {
        filesEl.innerHTML = '<div class="muted">Erro carregando arquivos</div>'
    }
    try {
        const comments = await api(`/api/projects/${projectId}/comments`)
        commentsEl.innerHTML = ''
        if (!comments.length) commentsEl.innerHTML = '<div class="muted">Nenhum comentário</div>'
        comments.forEach(c => {
            const div = document.createElement('div')
            div.className = 'item'
            div.innerHTML = `<div class="meta"><div>${c.text}</div></div><div class="sub">${new Date(c.ts||0).toLocaleString()}</div>`
            commentsEl.appendChild(div)
        })
    } catch (e) {
        commentsEl.innerHTML = '<div class="muted">Erro carregando comentários</div>'
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const sel = document.getElementById('projectSelect')
    if (sel) sel.addEventListener('change', (e) => loadProjectDetails(e.target.value))
    const uploadBtn = document.getElementById('projUploadBtn')
    if (uploadBtn) uploadBtn.addEventListener('click', async () => {
        const input = document.getElementById('projFileInput')
        const sel = document.getElementById('projectSelect')
        const pid = sel.value
        if (!pid) return alert('Selecione um projeto')
        const files = Array.from(input.files || [])
        if (!files.length) return alert('Selecione arquivos')
        try {
            const attachments = await Promise.all(files.map(f => new Promise((res, rej) => {
                const fr = new FileReader()
                fr.onload = () => res({ name: f.name, dataUrl: fr.result })
                fr.onerror = rej
                fr.readAsDataURL(f)
            })))
            await api(`/api/projects/${pid}/files`, { method: 'POST', body: JSON.stringify({ attachments }) })
            alert('Arquivos enviados')
            input.value = ''
            loadProjectDetails(pid)
        } catch (e) {
            console.error(e)
            alert('Erro ao enviar: ' + e.message)
        }
    })
    const commentBtn = document.getElementById('projCommentBtn')
    if (commentBtn) commentBtn.addEventListener('click', async () => {
        const input = document.getElementById('projCommentInput')
        const text = input.value.trim()
        const pid = document.getElementById('projectSelect').value
        if (!text) return alert('Escreva um comentário')
        try {
            await api(`/api/projects/${pid}/comments`, { method: 'POST', body: JSON.stringify({ text }) })
            input.value = ''
            loadProjectDetails(pid)
        } catch (e) {
            console.error(e)
            alert('Erro ao enviar comentário: ' + e.message)
        }
    })
    // inicial load
    try { loadProjects() } catch(e) {}
})
