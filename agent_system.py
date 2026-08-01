"""Agent CyberAI"""
import logging
from datetime import datetime
from typing import Dict, Optional
from uuid import uuid4
from config import CONFIG
from rag_pipeline import rag
from models.llm_backend import llm

logger = logging.getLogger("cyberai.agent")

class CyberAgent:
    def __init__(self):
        self.sessions = {}
        logger.info("Agent CyberAI prêt")
    
    async def process(self, question: str, session_id: Optional[str] = None, user_id: str = "anonymous") -> Dict:
        session_id = session_id or str(uuid4())
        
        docs = rag.search(question)
        context = ""
        if docs:
            context = "Documents:\n" + "\n".join([f"- {d['source']}: {d['content'][:300]}" for d in docs[:3]])
        
        risk = "low"
        if any(kw in question.lower() for kw in ["exploit","payload","reverse shell","bypass","0day"]):
            risk = "medium"
        
        response = llm.generate(question, context, risk)
        
        return {"session_id": session_id, "response": response, "risk_level": risk,
                "docs_retrieved": len(docs), "tools_called": 0, "error": None}

agent = CyberAgent()