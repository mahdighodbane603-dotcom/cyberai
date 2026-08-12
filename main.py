"""CyberAI - API FastAPI"""
import time, logging, base64
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Header, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, HTMLResponse
from config import CONFIG
from models.schemas import ChatRequest, ChatResponse, AgentStatus
from agent_system import agent
from rag_pipeline import rag
from tools.multimodal_processor import multimodal
from models.conversation_store import ConversationStore
from models.llm_backend import llm

store = ConversationStore()

logging.basicConfig(level=CONFIG.log_level)
logger = logging.getLogger("cyberai")

async def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(401, "Token requis")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or token != CONFIG.api_token:
        raise HTTPException(403, "Token invalide")

@asynccontextmanager
async def lifespan(app):
    logger.info("🚀 CyberAI prêt!")
    yield

app = FastAPI(title="CyberAI", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/status")
async def status():
    return AgentStatus(status="operational", collections_count=len(rag.collections), uptime_seconds=time.time())

@app.post("/chat")
async def chat(req: ChatRequest):
    # Conversation existante ? sinon on en crée une
    cid = req.conversation_id
    if not cid or not store.get(cid):
        cid = store.creer()

    # Sauvegarde du message utilisateur
    store.ajouter_message(cid, "user", req.message)

    # Mémoire de CETTE conversation (8 derniers messages)
    historique = store.historique_llm(cid, max_messages=8)
    reponse = llm.generate(req.message, req.contexte, historique=historique)

    # Sauvegarde de la réponse
    store.ajouter_message(cid, "assistant", reponse)
    return {"reponse": reponse, "conversation_id": cid}

@app.get("/api/conversations")
def liste_conversations():
    return store.lister()

@app.post("/api/conversations")
def nouvelle_conversation():
    return {"id": store.creer()}

@app.get("/api/conversations/{cid}")
def get_conversation(cid: str):
    conv = store.get(cid)
    if not conv:
        raise HTTPException(404, "Conversation introuvable")
    return conv

@app.delete("/api/conversations/{cid}")
def delete_conversation(cid: str):
    if not store.supprimer(cid):
        raise HTTPException(404, "Conversation introuvable")
    return {"ok": True}

@app.post("/analyze_image")
async def analyze_image(file: UploadFile = File(...), prompt: str = Form("Analyse cette image en cybersécurité"), auth=Depends(verify_token)):
    data = await file.read()
    if len(data) > 10*1024*1024: raise HTTPException(400, "Image trop volumineuse")
    ocr = multimodal.extract_text_ocr(data)
    analysis = multimodal.analyze_image(data, prompt)
    return {"ocr_text": ocr, "analysis": analysis}

@app.post("/speech_to_text")
async def stt(file: UploadFile = File(...), auth=Depends(verify_token)):
    data = await file.read()
    text = multimodal.speech_to_text(data)
    return {"transcription": text}

@app.post("/text_to_speech")
async def tts(text: str = Form(...), auth=Depends(verify_token)):
    audio = multimodal.text_to_speech(text)
    return Response(content=audio, media_type="audio/mpeg", headers={"Content-Disposition": "attachment; filename=cyberai.mp3"})

@app.post("/chat_with_audio")
async def chat_audio(audio: UploadFile = File(...), auth=Depends(verify_token)):
    data = await audio.read()
    user_text = multimodal.speech_to_text(data)
    if user_text.startswith("❌"): raise HTTPException(500, user_text)
    result = await agent.process(question=user_text)
    audio_resp = multimodal.text_to_speech(result["response"])
    return {"transcription": user_text, "text_response": result["response"],
            "audio_response_base64": base64.b64encode(audio_resp).decode(), "session_id": result["session_id"]}

@app.get("/demo", response_class=HTMLResponse)
async def demo():
    return HTMLResponse(r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberAI — Console</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Segoe UI',system-ui,sans-serif; background:#0f1117; color:#e6e9ef; height:100vh; display:flex; }
  /* Sidebar */
  #sidebar { width:280px; background:#161922; border-right:1px solid #232836; display:flex; flex-direction:column; }
  #sidebar header { padding:16px; border-bottom:1px solid #232836; }
  #sidebar h1 { font-size:18px; color:#6ee7b7; }
  #btnNouveau { width:100%; margin-top:12px; padding:10px; background:#10b981; color:#04231a; border:none; border-radius:8px; font-weight:700; cursor:pointer; font-size:14px; }
  #btnNouveau:hover { background:#34d399; }
  #liste { flex:1; overflow-y:auto; padding:8px; }
  .conv { padding:10px 12px; border-radius:8px; cursor:pointer; margin-bottom:4px; position:relative; display:flex; justify-content:space-between; align-items:center; gap:8px; }
  .conv:hover { background:#1e2430; }
  .conv.active { background:#10b98122; border:1px solid #10b98166; }
  .conv .titre { font-size:13px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; }
  .conv .meta { font-size:11px; color:#8a93a6; }
  .conv .del { visibility:hidden; background:none; border:none; color:#f87171; cursor:pointer; font-size:14px; }
  .conv:hover .del { visibility:visible; }
  .vide { color:#5b6472; font-size:13px; text-align:center; padding:20px; }
  /* Zone chat */
  #main { flex:1; display:flex; flex-direction:column; }
  #header { padding:14px 20px; border-bottom:1px solid #232836; font-size:15px; color:#aab3c5; }
  #header b { color:#e6e9ef; }
  #messages { flex:1; overflow-y:auto; padding:20px; display:flex; flex-direction:column; gap:12px; }
  .msg { max-width:75%; padding:12px 14px; border-radius:12px; font-size:14px; line-height:1.55; white-space:pre-wrap; word-wrap:break-word; }
  .msg.user { align-self:flex-end; background:#10b981; color:#04231a; border-bottom-right-radius:4px; }
  .msg.assistant { align-self:flex-start; background:#1e2430; border:1px solid #2a3140; border-bottom-left-radius:4px; }
  .msg.assistant code, .msg.user code { background:#0d1117; padding:2px 6px; border-radius:4px; font-family:Consolas,monospace; font-size:13px; }
  .msg.assistant pre { background:#0d1117; padding:10px; border-radius:8px; overflow-x:auto; margin:8px 0; }
  .msg.assistant pre code { background:none; padding:0; }
  #saisie { padding:16px 20px; border-top:1px solid #232836; display:flex; gap:10px; }
  #input { flex:1; background:#161922; border:1px solid #2a3140; border-radius:10px; padding:12px 14px; color:#e6e9ef; font-size:14px; resize:none; outline:none; }
  #input:focus { border-color:#10b981; }
  #btnEnvoyer { background:#10b981; border:none; border-radius:10px; color:#04231a; font-weight:700; padding:0 20px; cursor:pointer; font-size:14px; }
  #btnEnvoyer:disabled { opacity:.5; cursor:wait; }
  #etat { padding:6px 20px; font-size:12px; color:#8a93a6; }
</style>
</head>
<body>

<div id="sidebar">
  <header>
    <h1>🛡 CyberAI</h1>
    <button id="btnNouveau">＋ Nouvelle conversation</button>
  </header>
  <div id="liste"><div class="vide">Aucune conversation</div></div>
</div>

<div id="main">
  <div id="header">💬 <b id="titreConv">Nouvelle conversation</b></div>
  <div id="messages"><div class="vide">Écris ton premier message pour démarrer.</div></div>
  <div id="etat"></div>
  <div id="saisie">
    <textarea id="input" rows="2" placeholder="Message à CyberAI... (Entrée pour envoyer, Maj+Entrée pour sauter une ligne)"></textarea>
    <button id="btnEnvoyer">➤</button>
  </div>
</div>

<script>
let currentId = null;

// ---------- utilitaires ----------
async function api(url, options) {
  const r = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

function tempsRelatif(ts) {
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return "à l'instant";
  if (s < 3600) return Math.floor(s / 60) + ' min';
  if (s < 86400) return Math.floor(s / 3600) + ' h';
  return Math.floor(s / 86400) + ' j';
}

function echapper(texte) {
  const d = document.createElement('div');
  d.textContent = texte;           // neutre : pas d'exécution HTML
  return d.innerHTML;
}

function rendreMarkdown(texte) {
  // mini-rendu markdown (code, gras) — reste simple et sûr
  let t = echapper(texte);
  t = t.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  t = t.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  t = t.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  return t;
}

// ---------- interface ----------
function addMessage(role, contenu) {
  const zone = document.getElementById('messages');
  const vide = zone.querySelector('.vide');
  if (vide) vide.remove();
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  div.innerHTML = rendreMarkdown(contenu);
  zone.appendChild(div);
  zone.scrollTop = zone.scrollHeight;
}

function viderMessages() {
  document.getElementById('messages').innerHTML = '<div class="vide">Écris ton premier message pour démarrer.</div>';
}

function setTitre(t) {
  document.getElementById('titreConv').textContent = t || 'Nouvelle conversation';
}

async function chargerConversations() {
  try {
    const liste = await api('/api/conversations');
    const zone = document.getElementById('liste');
    zone.innerHTML = '';
    if (!liste.length) {
      zone.innerHTML = '<div class="vide">Aucune conversation</div>';
      return;
    }
    liste.forEach(c => {
      const d = document.createElement('div');
      d.className = 'conv' + (c.id === currentId ? ' active' : '');
      d.innerHTML =
        '<span class="titre">' + echapper(c.titre) + '</span>' +
        '<span class="meta">' + tempsRelatif(c.updated_at) + '</span>' +
        '<button class="del" title="Supprimer">🗑</button>';
      d.onclick = () => ouvrirConversation(c.id);
      d.querySelector('.del').onclick = (e) => supprimerConversation(c.id, e);
      zone.appendChild(d);
    });
  } catch (e) {
    console.error('Erreur chargement conversations :', e);
  }
}

async function ouvrirConversation(id) {
  try {
    const conv = await api('/api/conversations/' + id);
    currentId = id;
    viderMessages();
    conv.messages.forEach(m => addMessage(m.role, m.content));
    setTitre(conv.titre);
    chargerConversations();
  } catch (e) { console.error(e); }
}

async function supprimerConversation(id, ev) {
  ev.stopPropagation();
  if (!confirm('Supprimer définitivement cette conversation ?')) return;
  await api('/api/conversations/' + id, { method: 'DELETE' });
  if (currentId === id) nouveauChat();
  else chargerConversations();
}

function nouveauChat() {
  currentId = null;
  viderMessages();
  setTitre('Nouvelle conversation');
  chargerConversations();
  document.getElementById('input').focus();
}

// ---------- envoi ----------
async function envoyer() {
  const input = document.getElementById('input');
  const btn = document.getElementById('btnEnvoyer');
  const msg = input.value.trim();
  if (!msg || btn.disabled) return;

  btn.disabled = true;
  document.getElementById('etat').textContent = '⏳ Réflexion en cours...';
  addMessage('user', msg);
  input.value = '';

  try {
    if (!currentId) {
      const r = await api('/api/conversations', { method: 'POST' });
      currentId = r.id;
    }
    const r = await api('/chat', {
      method: 'POST',
      body: JSON.stringify({ message: msg, conversation_id: currentId })
    });
    addMessage('assistant', r.reponse);
    document.getElementById('etat').textContent = '';
    chargerConversations();
  } catch (e) {
    addMessage('assistant', '⚠️ Erreur : ' + e.message);
    document.getElementById('etat').textContent = '';
  } finally {
    btn.disabled = false;
    input.focus();
  }
}

// ---------- événements ----------
document.getElementById('btnEnvoyer').onclick = envoyer;
document.getElementById('btnNouveau').onclick = nouveauChat;
document.getElementById('input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); envoyer(); }
});

// ---------- démarrage ----------
chargerConversations();
document.getElementById('input').focus();
</script>
</body>
</html>""")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=CONFIG.api_host, port=CONFIG.api_port, reload=True)