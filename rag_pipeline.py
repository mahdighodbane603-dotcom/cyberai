"""Pipeline RAG - Base vectorielle ChromaDB"""
import hashlib, logging
from pathlib import Path
from typing import List
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from config import CONFIG

logger = logging.getLogger("cyberai.rag")

class CyberRAG:
    def __init__(self):
        logger.info("Chargement du modèle d'embedding...")
        self.embedding_model = SentenceTransformer("intfloat/multilingual-e5-large")
        
        self.chroma_client = chromadb.PersistentClient(
            path=CONFIG.vector_store_path,
            settings=Settings(anonymized_telemetry=False)
        )
        self.collections = {
            "cve": self._get_or_create("cve"),
            "exploit": self._get_or_create("exploit"),
            "technique": self._get_or_create("technique"),
        }
        logger.info(f"RAG prêt: {len(self.collections)} collections")
    
    def _get_or_create(self, name):
        try: return self.chroma_client.get_collection(name)
        except: return self.chroma_client.create_collection(name)
    
    def ingest_document(self, file_path: str, collection_name: str = "technique") -> int:
        path = Path(file_path)
        if not path.exists(): return 0
        collection = self.collections.get(collection_name)
        if not collection: return 0
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        chunks = []
        for i in range(0, len(content), 1024 - 128):
            chunk = content[i:i+1024]
            if len(chunk) > 50: chunks.append(chunk)
        
        if not chunks: return 0
        
        ids = [hashlib.md5(f"{path.name}_{i}".encode()).hexdigest() for i in range(len(chunks))]
        metadatas = [{"source": path.name, "chunk": i} for i in range(len(chunks))]
        embeddings = self.embedding_model.encode(chunks, normalize_embeddings=True).tolist()
        
        for start in range(0, len(chunks), 32):
            end = min(start+32, len(chunks))
            collection.add(embeddings=embeddings[start:end], documents=chunks[start:end],
                          metadatas=metadatas[start:end], ids=ids[start:end])
        
        logger.info(f"{len(chunks)} chunks ajoutés à '{collection_name}'")
        return len(chunks)
    
    def search(self, query: str, top_k: int = 5) -> List[dict]:
        query_emb = self.embedding_model.encode([query], normalize_embeddings=True).tolist()[0]
        results = []
        for name, col in self.collections.items():
            try:
                r = col.query(query_embeddings=[query_emb], n_results=top_k, include=["documents", "metadatas", "distances"])
                for i, doc in enumerate(r["documents"][0]):
                    sim = 1 - r["distances"][0][i]
                    if sim >= 0.65:
                        results.append({"content": doc[:500], "source": r["metadatas"][0][i].get("source","?"), "similarity": round(sim,3)})
            except: pass
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]

rag = CyberRAG()