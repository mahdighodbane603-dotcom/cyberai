from typing import Optional, List, Dict
from pydantic import BaseModel, Field, validator
import re

class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=65536)
    session_id: Optional[str] = None
    user_id: str = "anonymous"
    
    @validator("question")
    def sanitize_question(cls, v):
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', v).strip()

class ChatResponse(BaseModel):
    session_id: str
    response: str
    risk_level: str
    docs_retrieved: int
    tools_called: int
    processing_time_ms: float
    error: Optional[str] = None

class AgentStatus(BaseModel):
    status: str
    version: str = "2.0.0"
    collections_count: int
    uptime_seconds: float
    total_queries: int = 0
    active_sessions: int = 0