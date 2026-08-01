"""CyberAI - Configuration centralisée"""
import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

@dataclass
class CyberAIConfig:
    llm_provider: str = os.getenv("LLM_PROVIDER", "groq")
    llm_model: str = os.getenv("LLM_MODEL", "llama3-70b-8192")
    llm_temperature: float = 0.15
    llm_max_tokens: int = 4096
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    api_token: str = os.getenv("CYBERAI_API_TOKEN", "change-me")
    api_host: str = "0.0.0.0"
    api_port: int = int(os.getenv("PORT", "8000"))
    log_level: str = "INFO"
    multimodal_enabled: bool = True
    vector_store_path: str = "data/embeddings"
    knowledge_base_path: str = "data/knowledge_base"
    
    def __post_init__(self):
        Path(self.vector_store_path).mkdir(parents=True, exist_ok=True)
        Path(self.knowledge_base_path).mkdir(parents=True, exist_ok=True)

CONFIG = CyberAIConfig()