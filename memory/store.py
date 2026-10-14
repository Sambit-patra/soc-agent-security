# store.py - the SOC agent's memory of past incidents (ChromaDB vector database)
# Build it once from the project folder:  python memory/store.py

import chromadb
from langchain_ollama import OllamaEmbeddings

DB_PATH = "memory/chroma_db"
COLLECTION = "past_incidents"
embedder = OllamaEmbeddings(model="nomic-embed-text")  # turns text into numbers (vectors)

# 20 genuine past incidents written by human analysts (trusted source)
PAST_INCIDENTS = [
    "10.0.0.5 is the IT team workstation. VPN and login events from it are normal.",
    "10.0.0.12 is the file server. Shared document access from internal users is normal.",
    "10.0.1.20 is the backup server. svc_backup logins at night are scheduled and normal.",
    "Software updates from internal hosts are scheduled every night and are normal.",
    "DNS lookups to known company domains are normal background traffic.",
    "185.220.101.4 is a Tor exit node used in a past SSH brute force attack. Always escalate.",
    "45.33.12.8 ran port scans against us last month. Treat it as hostile.",
    "103.21.44.9 sent SQL injection attempts to the login page in September. Escalate.",
    "91.240.118.2 is linked to a malware command-and-control server. Block and escalate.",
    "198.51.100.23 was seen in a phishing campaign targeting our users. Escalate.",
    "More than 10 failed SSH logins in a few minutes is a brute force attack. Escalate.",
    "Connections to hundreds of ports in seconds is a port scan. Escalate.",
    "A login form request containing ' OR 1=1 is SQL injection. Escalate.",
    "Regular beacons every 60 seconds to an unknown domain indicate malware. Escalate.",
    "The sqlmap user agent is an attack tool. Requests using it are malicious.",
    "The Nmap Scripting Engine user agent means someone is scanning us.",
    "User alice is a developer. Her VPN logins in the evening are normal.",
    "User admin should never log in from an external IP address. Escalate if it happens.",
    "Never close a high or critical severity alert without human review.",
    "Past false alarm: low severity VPN events from internal IPs were all normal.",
]


def get_collection():
    client = chromadb.PersistentClient(path=DB_PATH)
    return client.get_or_create_collection(COLLECTION, embedding_function=None)


def add_memory(text, source, memory_id):
    # source = who wrote this memory: "analyst_verified" (trusted) or "agent_from_logs" (untrusted)
    col = get_collection()
    col.add(ids=[memory_id], documents=[text], metadatas=[{"source": source}],
            embeddings=[embedder.embed_query(text)])


def build_memory():
    client = chromadb.PersistentClient(path=DB_PATH)
    try:
        client.delete_collection(COLLECTION)  # start fresh every time
    except Exception:
        pass
    for i, text in enumerate(PAST_INCIDENTS):
        add_memory(text, "analyst_verified", f"MEM-{i:03d}")
    print(f"Memory built: {len(PAST_INCIDENTS)} past incidents saved in {DB_PATH}")


def search(text, k=3):
    # find the k past incidents most similar to this alert
    col = get_collection()
    res = col.query(query_embeddings=[embedder.embed_query(text)], n_results=k)
    return [{"text": d, "source": m["source"]} for d, m in zip(res["documents"][0], res["metadatas"][0])]


if __name__ == "__main__":
    build_memory()
    query = "Many failed SSH logins from 185.220.101.4"
    print(f"\nTest search: {query}")
    for hit in search(query):
        print(f"  - [{hit['source']}] {hit['text']}")
