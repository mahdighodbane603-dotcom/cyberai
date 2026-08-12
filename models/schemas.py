from pydantic import BaseModel
from typing import Optional


class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    contexte: str = ""


class ChatResponse(BaseModel):
    reponse: str
    conversation_id: str


class AgentStatus(BaseModel):
    status: str
    collections_count: int
    uptime_seconds: float