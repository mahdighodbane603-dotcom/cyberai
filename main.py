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

@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, auth=Depends(verify_token)):
    start = time.time()
    result = await agent.process(question=req.question, session_id=req.session_id, user_id=req.user_id)
    return ChatResponse(session_id=result["session_id"], response=result["response"],
        risk_level=result["risk_level"], docs_retrieved=result["docs_retrieved"],
        tools_called=result["tools_called"], processing_time_ms=round((time.time()-start)*1000,2))

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
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>CyberAI</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:Segoe UI,sans-serif;background:#0a0e27;color:#e0e0e0;padding:20px}}
.container{{max-width:700px;margin:auto}}
h1{{color:#00ff88;text-align:center}} .card{{background:#1a1f3a;border-radius:12px;padding:20px;margin:20px 0;border:1px solid #2a2f5a}}
textarea,input[type=file]{{width:100%;padding:10px;border-radius:8px;border:1px solid #3a3f6a;background:#0d1230;color:#e0e0e0;margin:10px 0}}
button{{background:#00ff88;color:#0a0e27;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:bold;margin:5px}}
.result{{background:#0d1230;border-radius:8px;padding:15px;margin-top:15px;border-left:4px solid #00ff88;white-space:pre-wrap}}
.hidden{{display:none}} .recording{{animation:pulse 1s infinite;background:#ff4444!important}}
@keyframes pulse{{0%,100%{{transform:scale(1)}}50%{{transform:scale(1.05)}}}}
</style></head><body>
<div class=container><h1>🛡️ CyberAI</h1><p style=color:#888;text-align:center>Assistant Cybersécurité</p>
<div class=card><h2>💬 Chat</h2><textarea id=chatInput rows=3 placeholder="Pose ta question..."></textarea>
<button onclick=sendChat()>Envoyer</button><div id=chatResult class="result hidden"></div></div>
<div class=card><h2>🖼️ Image</h2><input type=file id=imageInput accept=image/*>
<button onclick=sendImage()>Analyser</button><div id=imageResult class="result hidden"></div></div>
<div class=card><h2>🎤 Audio</h2><button id=recordBtn class=recording onclick=toggleRecording()>🎤 Enregistrer</button>
<div id=audioResult class="result hidden"></div><audio id=audioPlayer class=hidden controls style=width:100%></audio></div></div>
<script>
const T='{CONFIG.api_token}',U=window.location.origin;
async function sendChat(){{const r=document.getElementById('chatResult');r.classList.remove('hidden');r.textContent='⏳...';
const d=await(await fetch(U+'/chat',{{method:'POST',headers:{{'Authorization':'Bearer '+T,'Content-Type':'application/json'}},body:JSON.stringify({{question:document.getElementById('chatInput').value}})}})).json();
r.textContent=d.response||'Erreur'}}
async function sendImage(){{const f=document.getElementById('imageInput').files[0];if(!f)return alert('Sélectionne une image');
const fd=new FormData();fd.append('file',f);const r=document.getElementById('imageResult');r.classList.remove('hidden');r.textContent='⏳...';
const d=await(await fetch(U+'/analyze_image',{{method:'POST',headers:{{'Authorization':'Bearer '+T}},body:fd}})).json();
r.textContent='📄 OCR: '+(d.ocr_text||'rien')+'\\n\\n🤖 Analyse: '+(d.analysis||'')}}
let mr,chunks=[],rec=false;
async function toggleRecording(){{const b=document.getElementById('recordBtn');
if(!rec){{chunks=[];const s=await navigator.mediaDevices.getUserMedia({{audio:true}});mr=new MediaRecorder(s);
mr.ondataavailable=e=>chunks.push(e.data);mr.onstop=async()=>{{const blob=new Blob(chunks,{{type:'audio/webm'}});
const fd=new FormData();fd.append('audio',blob);const r=document.getElementById('audioResult');r.classList.remove('hidden');r.textContent='⏳...';
const d=await(await fetch(U+'/chat_with_audio',{{method:'POST',headers:{{'Authorization':'Bearer '+T}},body:fd}})).json();
r.textContent='📝 Toi: '+d.transcription+'\\n\\n🤖 CyberAI: '+d.text_response;
if(d.audio_response_base64){{const p=document.getElementById('audioPlayer');p.src='data:audio/mpeg;base64,'+d.audio_response_base64;p.classList.remove('hidden');p.play()}}}};
mr.start();rec=true;b.textContent='⏹️ Arrêter';b.classList.add('recording')}}
else{{mr.stop();rec=false;b.textContent='🎤 Enregistrer';b.classList.remove('recording')}}}}
</script></body></html>""")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=CONFIG.api_host, port=CONFIG.api_port, reload=True)