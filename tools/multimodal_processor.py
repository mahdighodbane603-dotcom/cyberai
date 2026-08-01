"""Traitement images et audio"""
import io, base64, logging, tempfile
from pathlib import Path
from dataclasses import dataclass
from PIL import Image
import httpx

logger = logging.getLogger("cyberai.multimodal")

@dataclass
class MMConfig:
    vision_provider: str = "llava"
    stt_provider: str = "whisper"
    tts_provider: str = "gtts"
    ollama_base: str = "http://localhost:11434"

class MultimodalProcessor:
    def __init__(self, config: MMConfig = None):
        self.config = config or MMConfig()
        self.http = httpx.Client(timeout=120)
        logger.info("Multimodal prêt")
    
    def encode_image(self, img_data: bytes, max_size=2048):
        img = Image.open(io.BytesIO(img_data))
        if max(img.size) > max_size:
            r = max_size / max(img.size)
            img = img.resize((int(img.size[0]*r), int(img.size[1]*r)), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format=img.format or "PNG")
        return base64.b64encode(buf.getvalue()).decode(), (img.format or "png").lower()
    
    def analyze_image(self, img_data: bytes, prompt="Décris cette image"):
        b64, _ = self.encode_image(img_data)
        try:
            r = self.http.post(f"{self.config.ollama_base}/api/generate",
                json={"model":"llava:13b","prompt":prompt,"images":[b64],"stream":False}, timeout=120)
            return r.json()["response"]
        except Exception as e:
            return f"⚠️ Erreur: {e}"
    
    def extract_text_ocr(self, img_data: bytes) -> str:
        try:
            import pytesseract
            return pytesseract.image_to_string(Image.open(io.BytesIO(img_data)), lang="fra+eng").strip()
        except Exception as e:
            return f"⚠️ OCR: {e}"
    
    def speech_to_text(self, audio_data: bytes) -> str:
        try:
            import whisper
            model = whisper.load_model("base")
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(audio_data); p = tmp.name
            text = model.transcribe(p, language="fr", fp16=False)["text"].strip()
            Path(p).unlink(missing_ok=True)
            return text
        except ImportError:
            return "❌ Installe whisper: pip install openai-whisper"
        except Exception as e:
            return f"⚠️ STT: {e}"
    
    def text_to_speech(self, text: str) -> bytes:
        try:
            from gtts import gTTS
            tts = gTTS(text=text[:5000], lang="fr", slow=False)
            buf = io.BytesIO(); tts.write_to_fp(buf); buf.seek(0)
            return buf.read()
        except Exception as e:
            logger.error(f"TTS: {e}")
            import struct, wave
            buf = io.BytesIO()
            with wave.open(buf,"wb") as w: w.setnchannels(1); w.setsampwidth(2); w.setframerate(22050); w.writeframes(struct.pack("<h",0)*22050)
            buf.seek(0)
            return buf.read()

multimodal = MultimodalProcessor()