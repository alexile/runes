# Stream

Stream processing: backpressure, dedupe, windowing, watermarks, ingest.

| Crate | Description |
| --- | --- |
| [`rune-bp-channel`](rune-bp-channel) | Bounded channel wrapper with configurable backpressure policy: drop-oldest, drop-newest, block |
| [`rune-canonical-event`](rune-canonical-event) | Typed event envelope for streaming pipelines — source, timestamp, sequence, kind, payload, and metadata, with a validating builder |
| [`rune-checkpoint`](rune-checkpoint) | Resumable-cursor/offset persistence for restartable stream consumers |
| [`rune-dedupe`](rune-dedupe) | Idempotency/dedup filter over a keyed, windowed stream |
| [`rune-heartbeat`](rune-heartbeat) | Missing-heartbeat/liveness detector over a keyed stream of pings |
| [`rune-ingest-mqtt`](rune-ingest-mqtt) | Minimal MQTT subscriber normalizing messages into a typed event channel |
| [`rune-ingest-ndjson`](rune-ingest-ndjson) | Streaming NDJSON reader with a time-compression replay clock (Nx speed) |
| [`rune-multiplex`](rune-multiplex) | Fan-in merge of N ordered sources into one interleaved, time-ordered stream |
| [`rune-rate-rule`](rune-rate-rule) | Composable rule trait plus threshold, rate-of-change, and missing-heartbeat rule implementations |
| [`rune-reorder`](rune-reorder) | Windowed reordering buffer for out-of-sequence timestamped/sequenced items |
| [`rune-retry-queue`](rune-retry-queue) | Dead-letter queue with configurable backoff retry for failed sink writes |
| [`rune-schema-sniff`](rune-schema-sniff) | Heuristic column/field-type detector for arbitrary CSV/JSON: guesses timestamp/id/value/lat-lon columns, emits a normalized preview with confidence scores |
| [`rune-watermark`](rune-watermark) | Late-arrival/watermark tracking for out-of-order event streams |
| [`rune-window-agg`](rune-window-agg) | Tumbling/sliding/session window aggregator over a timestamped stream |

[All groups](../../README.md)
