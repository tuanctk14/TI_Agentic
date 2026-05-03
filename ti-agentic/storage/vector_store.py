import chromadb
from sentence_transformers import SentenceTransformer

# Khởi tạo ChromaDB lưu xuống thư mục local
client = chromadb.PersistentClient(path="./data/chroma_db")

# Model để tạo vector embedding
embedder = SentenceTransformer('all-MiniLM-L6-v2')

# Tạo 2 collections
ioc_collection = client.get_or_create_collection("ioc_history")
report_collection = client.get_or_create_collection("threat_reports")

def save_ioc(ioc: dict):
    """Lưu IOC vào vector DB"""
    text = f"{ioc['name']} {ioc.get('description', '')} {ioc.get('ioc_type', '')}"
    embedding = embedder.encode(text).tolist()
    
    ioc_collection.upsert(
        ids=[ioc['id']],
        embeddings=[embedding],
        documents=[text],
        metadatas=[{
            "name": ioc['name'],
            "risk_level": ioc.get('risk_level', 'unknown'),
            "ioc_type": ioc.get('ioc_type', 'unknown'),
            "pattern": ioc.get('pattern', '')
        }]
    )

def search_similar_iocs(query: str, n_results: int = 5) -> list:
    """Tìm IOC tương tự qua semantic search"""
    query_embedding = embedder.encode(query).tolist()
    
    results = ioc_collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results
    )
    
    return [
        {"name": meta["name"], "risk": meta["risk_level"], 
         "type": meta["ioc_type"], "pattern": meta["pattern"]}
        for meta in results["metadatas"][0]
    ]

def save_threat_report(report_id: str, content: str, metadata: dict):
    """Lưu báo cáo threat intelligence"""
    embedding = embedder.encode(content[:512]).tolist()
    report_collection.upsert(
        ids=[report_id],
        embeddings=[embedding],
        documents=[content],
        metadatas=[metadata]
    )