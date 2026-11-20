# Chain (LLM)

LLM orchestration: core traits, OpenAI/Anthropic/Gemini/Ollama providers, prompts, memory, agents, tools, RAG and MCP.

| Crate | Description |
| --- | --- |
| [`rune-chain`](rune-chain) | One-dependency LLM toolkit: OpenAI/Anthropic/Gemini/Ollama clients, agents with tools, RAG and memory, typed extraction, streaming. Re-exports the rune-chain stack behind features |
| [`rune-chain-agent`](rune-chain-agent) | Hardened tool-calling agents for rune-chain: ReAct and native function calling with schema validation, limits, approval and fenced tool output |
| [`rune-chain-anthropic`](rune-chain-anthropic) | Anthropic Claude LLM provider for the rune-chain framework — Messages API client with streaming, prompt caching, thinking and structured output |
| [`rune-chain-autonomous`](rune-chain-autonomous) | Budgeted autonomous agent for rune-chain: plans and runs tasks toward a goal under hard limits, with loop detection, approval-gated tools, checkpoints and events |
| [`rune-chain-conversational`](rune-chain-conversational) | ConversationalChain for rune-chain: multi-turn dialogue with a pinned system prompt, bounded token-budget or summary memory, and streams recorded in memory |
| [`rune-chain-core`](rune-chain-core) | Core traits and types for the rune-chain LLM orchestration framework |
| [`rune-chain-embed`](rune-chain-embed) | Embedder trait, hardened OpenAI-compatible/Cohere/Voyage/Jina embedding providers, batching and caching for the rune-chain LLM framework |
| [`rune-chain-gemini`](rune-chain-gemini) | Google Gemini LLM provider for rune-chain: Gemini API and Vertex AI, streaming, tools, structured output, thinking, safety settings and embeddings |
| [`rune-chain-graph`](rune-chain-graph) | Stateful graph orchestration for LLM workflows and agents: typed state with reducers, parallel supersteps, checkpoints, time travel, human-in-the-loop interrupts and a prebuilt ReAct agent |
| [`rune-chain-knowledge-graph`](rune-chain-knowledge-graph) | GraphRAG for the rune-chain LLM framework: schema-validated entity and relation extraction, entity resolution, provenance, and bounded k-hop retrieval with cited context |
| [`rune-chain-llm`](rune-chain-llm) | LlmChain for rune-chain: prompt template + LLM + memory, with structured output, output parsers, streaming into memory, usage and finish reason |
| [`rune-chain-loader`](rune-chain-loader) | Hardened document loaders for rune-chain RAG: text, HTML, JSON, JSON Lines, CSV and jailed directory walks with limits |
| [`rune-chain-macros`](rune-chain-macros) | Proc macros for rune-chain: #[tool] turns a function into an LLM tool with a generated JSON Schema, #[derive(Embed)] marks the text fields to embed |
| [`rune-chain-memory`](rune-chain-memory) | In-process conversation memory for rune-chain: windowed, token-budget and summary buffers, plus optional vector-retrieval and entity memories |
| [`rune-chain-ollama`](rune-chain-ollama) | Ollama (local models) provider for rune-chain: streaming, native tool calls, structured output, embeddings, model management |
| [`rune-chain-openai`](rune-chain-openai) | OpenAI and OpenAI-compatible (Azure, Mistral, Groq, Together, DeepSeek, OpenRouter, vLLM, LM Studio) LLM provider for rune-chain: streaming, tools, structured output |
| [`rune-chain-output-parser`](rune-chain-output-parser) | Typed LLM output for rune-chain: instructor-style extraction with re-ask, JSON Schema validation, partial streaming, and classic parsers |
| [`rune-chain-parallel`](rune-chain-parallel) | ParallelChain for rune-chain: fan-out with bounded concurrency, per-branch timeouts, fail-fast cancellation or collect-all errors, ordered outputs and summed usage |
| [`rune-chain-prompt`](rune-chain-prompt) | Prompt template engine for the rune-chain LLM orchestration framework |
| [`rune-chain-retrieval`](rune-chain-retrieval) | RAG for rune-chain: RetrievalQaChain, BM25, hybrid fusion (RRF), MMR, multi-query and Cohere/Jina/Voyage reranking |
| [`rune-chain-retry`](rune-chain-retry) | Resilience and routing for rune-chain Llm: retries with jittered backoff, multi-provider router with circuit breakers |
| [`rune-chain-sequential`](rune-chain-sequential) | SequentialChain for rune-chain: ordered pipelines with build-time key checks, input/output mapping, per-step timeouts and retries, early exit, step events and summed usage |
| [`rune-chain-splitter`](rune-chain-splitter) | Text splitters for RAG: semantic (embedding-based), recursive, markdown and token chunking with citation offsets |
| [`rune-chain-tools`](rune-chain-tools) | Standard LLM-callable tool implementations for rune-chain: encoding, hashing, graph, entropy, and more |
| [`rune-chain-usage`](rune-chain-usage) | Per-provider token and cost accounting with budget caps for rune-chain LLMs |
| [`rune-mcp`](rune-mcp) | Hardened MCP client and server on rmcp: rune tools, resources and prompts, namespaced multi-server tool sets, policy, caps and fencing |
| [`rune-otel-genai`](rune-otel-genai) | OpenTelemetry GenAI semantic-convention spans for rune-chain LLM calls, tool executions and agents — model, tokens, cost and errors |
| [`rune-tool-schema`](rune-tool-schema) | Tool definitions for LLM function calling: MCP descriptor, OpenAI/Anthropic/Gemini export with schema lint, argument validation and text hygiene |
| [`rune-vectorstore`](rune-vectorstore) | Vector stores for RAG: async trait, exact and HNSW in-memory indexes, JSON metadata filters, MMR and checksummed snapshots |
| [`rune-vectorstore-pgvector`](rune-vectorstore-pgvector) | PostgreSQL + pgvector backend for rune-vectorstore: HNSW or IVFFlat indexes, batched upserts, metadata filters as bound jsonb conditions |
| [`rune-vectorstore-qdrant`](rune-vectorstore-qdrant) | Qdrant backend for rune-vectorstore over the REST API: collections, batched upserts, filtered search, delete by id or filter, bounded responses |
| [`rune-vectorstore-sqlite`](rune-vectorstore-sqlite) | Embedded single-file SQLite vector store for rune-vectorstore: exact search with a bounded top-k scan, WAL, bound JSON metadata filters |

[All groups](../../README.md)
