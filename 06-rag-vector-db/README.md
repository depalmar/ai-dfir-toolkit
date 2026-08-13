# 06 — RAG & Vector Database Attack Detection

Detects attacks against retrieval-augmented generation pipelines and vector databases: ChromaDB, Pinecone, Weaviate, Qdrant, Milvus, pgvector. Covers RAG poisoning, vector DB exposure, embedding inversion, and ingestion-time tampering.

## Threats covered

| Threat | ATLAS | OWASP | Reference |
|--------|-------|-------|-----------|
| RAG document poisoning | T0020 | LLM09 | PoisonedRAG (USENIX 2025) |
| AgentPoison (RAG-based agent poisoning) | T0020, T0051 | LLM09 | NeurIPS 2024 |
| Unauthenticated vector DB exposure | T0011 | LLM09 | Shodan 2024 (12K+ exposed) |
| Embedding inversion attacks | T0024 | LLM09 | Princeton research |
| Indirect prompt injection via RAG | T0051.001 | LLM01 | Greshake et al. |
| Bulk vector DB exfiltration | T0024 | LLM02 | — |

## Files

- `vector_db_unauth_exposure.rules` — Suricata for exposed Chroma/Weaviate/Qdrant/Milvus
- `vector_db_bulk_exfil.yml` — Sigma for high-volume vector retrieval
- `rag_document_hidden_text.yar` — YARA for white-text / Unicode hidden instructions
- `chroma_sqlite_unexpected_writer.yml` — Sigma for ChromaDB persistence tampering
- `vector_db_query_anomaly.yml` — Sigma for vector DB port access and RAG injection ingestion

## Log sources required

- Network telemetry (Suricata, Zeek) for vector DB ports
- Application logs from vector DBs (often stdout/stderr, ship via Filebeat/Vector)
- File modification events for embedded SQLite stores (ChromaDB)
- Document ingestion logs from RAG frameworks (LangChain, LlamaIndex, Haystack)
- File contents for YARA scanning of RAG source documents

## Default ports & artifact locations

| Vector DB | Port(s) | Storage |
|-----------|---------|---------|
| ChromaDB | 8000 | `./chroma_data/`, `chroma.sqlite3` |
| Weaviate | 8080 | `/var/lib/weaviate/` |
| Qdrant | 6333 (REST), 6334 (gRPC) | `./storage/` |
| Milvus | 19530 (gRPC), 9091 (metrics) | etcd metadata + MinIO/S3 |
| pgvector | 5432 (PostgreSQL) | PostgreSQL data dir + `pg_stat_statements` |
| Pinecone | (managed SaaS) | n/a — use console audit logs |

## Tuning notes

The "bulk exfil" rule needs **per-environment baselining** — production RAG apps legitimately make hundreds of retrieval calls per minute. Focus the alert on **anomalous principals** (new IAM users, IPs from unexpected ASNs) rather than raw volume. The hidden-text YARA rule has higher FP potential against legitimate documents that use white text for accessibility reasons (alt text, screen-reader hints) — pair with content-type and ingestion-source filters.
