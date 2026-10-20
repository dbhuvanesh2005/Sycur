# SYCUR Local Policy RAG PoC

## Existing infrastructure
- Ollama running locally
- `bge-m3` installed for embeddings
- `qwen3.5:9b` installed for answer generation
- PostgreSQL database: `sycur_rag_poc`
- `pgvector` extension and `policy_chunks` table already created

## Project setup
From the project root, with the virtual environment active:

```bash
pip install -e .
cp .env.example .env
```

Edit `.env` and set the PostgreSQL password. Never hardcode the password in Python.

## Required document
Keep this file at:

```text
documents/Access Management Policy.docx
```

## Ingest

```bash
python -m scripts.ingest
```

For the current policy document, the structure-aware parser should produce Purpose, Scope, AM-01 through AM-13, and Policy Sanctions.

## Search + local LLM answer

```bash
python -m scripts.search "What does the policy require for least privilege on code repositories?"
```

Flow:

```text
Question -> bge-m3 -> pgvector similarity search -> top policy chunks -> qwen3.5:9b -> grounded structured answer
```
# Sycur
