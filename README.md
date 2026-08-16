# Mycelium

A dark web (Tor `.onion`) infrastructure correlation and discovery tool, built as a cybersecurity intelligence master's thesis (TFM) project. It crawls onion services through Tor, extracts technical artifacts from each one, and correlates domains that share infrastructure — surfacing cases where operators who believed they were running unrelated, anonymous sites are, in fact, linked by a shared certificate, server key, tracking library, or wallet address.

Much like mycelium connects organisms that appear completely separate above ground, this tool reveals the shared infrastructure beneath domains that appear entirely unrelated on the surface.

The methodology is inspired by [OnionScan](https://github.com/s-rah/onionscan) (Sarah Jamie Lewis, 2016), extended with several additional correlation signals (JARM TLS fingerprinting, PGP keys, cryptocurrency addresses, and hashed HTML sub-resources) that did not exist in the original tool.

> **Academic context**: this project was built as part of a university master's thesis. It is a research and educational tool, not a production security product. See [Safety & Ethics](#safety--ethics) below for the guardrails built into the pipeline.

> **Project status**: this has stayed a design-and-implementation project throughout, not a production deployment. There has been one real scan (~8,500 domains) used to build and validate the pipeline, the dashboard, and the case-study generation — not a continuously-run, long-term crawl. The optional LLM summarization/categorization has been validated in small, controlled batches (see [Troubleshooting](#troubleshooting-the-llm-backfill-scripts)), not run to completion over the full dataset. Numbers and examples throughout this README and the codebase reflect that real, if partial, dataset — they are not illustrative placeholders, but they also shouldn't be read as a finished, exhaustive survey.

---

## Table of contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup — step by step](#setup--step-by-step)
- [Running a scan](#running-a-scan)
- [Running the dashboard](#running-the-dashboard)
- [Optional: jurisdiction hint map](#optional-jurisdiction-hint-map)
- [Running the tests](#running-the-tests)
- [Troubleshooting the LLM backfill scripts](#troubleshooting-the-llm-backfill-scripts)
- [Safety & ethics](#safety--ethics)
- [Known limitations](#known-limitations)
- [Further reading](#further-reading)

---

## What it does

1. **Discovers** onion domains from a seed source (currently the Ahmia index).
2. **Enumerates** each domain: which ports are open, HTTP title, `Server` header, detected technologies.
3. **Filters** every domain through a mandatory, non-optional safe-mode check (hash-based blocklist) *before* anything else touches it.
4. **Extracts correlation artifacts** from each reachable domain, without ever storing the raw page content:
   - TLS certificate (SHA-256 of the DER-encoded cert)
   - JARM fingerprint (TLS stack/configuration fingerprint, independent of the certificate)
   - SSH host key fingerprint
   - PGP public key (if published on the page)
   - Cryptocurrency addresses mentioned in the page text (BTC, XMR, ETH)
   - Hashes of same-origin linked resources: JavaScript, CSS, favicon, and linked documents (PDF/DOCX/XLSX/ZIP)
   - Fuzzy hash of the page content (for near-duplicate detection)
5. **Correlates** domains that share any of the above, with a documented reliability hierarchy (exact identity artifacts like a shared certificate outrank weaker signals like shared JARM, which in turn outrank fuzzy content similarity).
6. **Stores** the resulting graph in Neo4j and a searchable index in Elasticsearch.
7. **Serves a web dashboard** (FastAPI + vanilla JS) to search, browse, and explore the correlation graph per domain — including an optional interactive 3D view.
8. **Generates a case-study report** automatically: it finds the strongest real example of infrastructure correlation in your own dataset and writes it up in Markdown, ready to drop into the thesis.

## How it works

```
   Seed source (Ahmia)
          |
          v
    [ Discovery ]  ->  candidate .onion addresses
          |
          v
  [ Safe-mode filter ]  ->  hash-checked against blocklist, BEFORE anything else
          |
          v
   [ Enumeration ]  ->  open ports, HTTP title, Server header, tech fingerprint
          |
          v
   [ Correlation ]  ->  TLS cert, JARM, SSH key, PGP key, crypto addresses,
                         hashed HTML sub-resources, fuzzy content hash
          |
          +----------------------+
          v                      v
   [ Neo4j graph ]        [ Elasticsearch index ]
          |                      |
          +----------+-----------+
                     v
            [ Web dashboard ]
         (search, browse, 2D/3D
          relationship graphs)
                     |
                     v
       [ Case-study generator ] -> Markdown report
```

Everything runs through Tor (`stem` for circuit control, `PySocks`/`aiohttp-socks` for SOCKS5 transport). Nothing bypasses Tor, including the safe-mode blocklist download itself in production mode.

## Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Tor transport | `stem`, `PySocks`, `aiohttp-socks` | Circuit rotation every N requests |
| TLS / crypto | `cryptography`, `pyJARM` | JARM's own transport isn't used (HTTP-proxy only); only its packet/hash construction is reused over a Tor-routed socket |
| SSH fingerprinting | `paramiko` | |
| Fuzzy hashing | `ppdeep` | Pure-Python reimplementation of the `ssdeep` algorithm — chosen because `ssdeep` has no prebuilt Windows wheel and requires a C toolchain |
| Graph database | Neo4j 5 Community (Docker) | |
| Search index | Elasticsearch 8.15 (Docker) | |
| Backend | FastAPI + `uvicorn` | |
| Frontend | Vanilla HTML/CSS/JS (no build step) | |
| Optional 3D view | `three.js`, `3d-force-graph`, `three-spritetext` (CDN, lazy-loaded) | Only fetched the first time the user opens the 3D view |
| Tests | `pytest` | |

## Project structure

```
mycelium/
  config.py                    Global configuration (SAFE_MODE is a source-code
                                constant, deliberately never read from an env var)
  requirements.txt
  docker-compose.yml           Tor + Neo4j + Elasticsearch for local development
  .env.example                 Template for local credentials (copy to .env)

  src/
    tor_client.py               Tor circuit management (stem)
    safe_mode.py                Mandatory pre-filter against the Ahmia blocklist
    models.py                   Pydantic data models
    crawler.py                  Frontier + async fetcher + parser
    enumeration.py              Port scanning, tech fingerprinting
    correlation.py              Artifact extraction + correlation logic
    jarm_fingerprint.py         JARM hash computation over Tor
    artifact_extraction.py      PGP key / crypto address extraction from page text
    html_artifact_extraction.py Same-origin JS/CSS/favicon/document link extraction
    graph.py                    Neo4j read/write layer
    search_index.py             Elasticsearch read/write layer
    jurisdiction_hint.py        Weak jurisdiction hint from already-stored cert/title data, no network
    ollama_client.py            Minimal HTTP client for a local Ollama instance (opt-in LLM features)
    html_text_extraction.py     HTML-to-plain-text conversion, as input for the local LLM
    summary_cache.py            Cache keyed by content hash, to avoid redundant LLM calls
    circuit_breaker.py          Backs off after repeated Ollama failures during a large backfill run
    progress_bar.py             Terminal progress bar with a live ETA, for long-running backfill scripts
    seeds/
      base.py                    Abstract SeedSource interface
      ahmia.py                    Ahmia adapter (listing + official blocklist)

  scripts/
    run_batch.py                 Main large-scale scan, resumable via checkpoints
    backfill_jarm.py              Fill in JARM for an existing checkpoint
    backfill_artifacts.py         Fill in PGP/crypto/HTML-artifacts for an existing checkpoint
    backfill_summaries.py         Fill in local-LLM content summaries for an existing checkpoint (opt-in)
    backfill_categories.py        Classify service type from an already-generated summary (opt-in, no Tor needed)
    backfill_jurisdiction.py      Weak jurisdiction hint from cert/title data already in the checkpoint (no network at all)
    backfill_llm_related_domains.py  Summary + category, but ONLY for domains with a confirmed relation (demo-friendly, much smaller scope)
    recorrelate.py                 Recompute correlation + reload DBs without rescanning
    generate_case_study.py         Auto-generate the F7 case-study Markdown report
    manual_test.py                 Quick single-domain smoke test
    diagnose_tor.py                 Tor connectivity diagnostics

  webapp/
    main.py                      FastAPI app + API endpoints
    static/                      Dashboard frontend (HTML/CSS/JS)

  tests/                        pytest suite (253 tests)
  data/                         Checkpoints and generated case studies (gitignored
                                 except for small sample/report files)
  docs/
    DECISIONS.md                  Chronological engineering log (in Spanish):
                                   bugs found, scaling fixes, and the reasoning
                                   behind non-obvious design choices
```

## Prerequisites

- Python 3.11+ (3.12 recommended; see the note on Python 3.14 below)
- [Docker](https://www.docker.com/) and Docker Compose
- ~4 GB of free RAM for Neo4j + Elasticsearch running locally

### A note on Python 3.14 (or any very recent version)

Two dependencies (`pydantic`, `cryptography`) use native Rust extensions. On a very new Python interpreter, the exact version pinned in `requirements.txt` may not yet have a prebuilt wheel, and `pip install` will try to compile from source — which fails without a Rust/C build toolchain (typical error: "failed to build wheel", mentions of `maturin`/`cargo`/PyO3). That's why those two dependencies are left unpinned (`>=`) rather than pinned to an exact version, so `pip` can pick a version with an available wheel for your interpreter. If installation still fails, upgrade `pip` first (`python3 -m pip install --upgrade pip`) and retry.

## Setup — step by step

### 1. Clone the repository

```bash
git clone https://github.com/4sur3/Mycelium.git
cd Mycelium
```

### 2. (Optional) configure local credentials

The project works out of the box with built-in development defaults — you only need this step if you want to change them.

```bash
cp .env.example .env
# edit .env if you want different local credentials for Tor/Neo4j
```

### 3. Start the supporting services

```bash
docker compose up -d
```

This starts three containers: `onion-infra-tor` (SOCKS5 proxy + control port), `onion-infra-neo4j` (graph database, browser UI at `http://localhost:7474`), and `onion-infra-es` (Elasticsearch, `http://localhost:9200`).

Wait for Elasticsearch to report healthy before scanning:

```bash
curl http://localhost:9200/_cluster/health
# wait for "status":"yellow" or "status":"green"
```

### 4. Install Python dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 5. Verify Tor connectivity

```bash
python3 scripts/diagnose_tor.py
```

### 6. Run a quick smoke test

```bash
python3 scripts/manual_test.py
```

If this succeeds, you're ready to run a real scan.

## Running a scan

### Full scan

```bash
python3 scripts/run_batch.py --limit 10000
```

Processes domains in checkpointed batches (`config.BATCH_CHECKPOINT_SIZE`, 200 by default), saving progress to `data/checkpoint_<date>.jsonl` after every batch. If interrupted (Ctrl+C, power loss, sleep), just rerun the same command on the same day — it resumes automatically without repeating already-processed domains.

### Filling in data added after a previous scan

If you scanned before a given signal existed in the codebase, you don't need to rescan from scratch:

```bash
# JARM only (domains with port 443 already known)
python3 scripts/backfill_jarm.py --checkpoint data/checkpoint_<date>.jsonl

# PGP + crypto addresses + HTML sub-resource hashes, in one pass
python3 scripts/backfill_artifacts.py --checkpoint data/checkpoint_<date>.jsonl
```

### Recovering from a crash in the final step (no rescanning)

If a scan or backfill completed the network-heavy part successfully but failed while saving/correlating at the end, the checkpoint already has everything needed:

```bash
python3 scripts/recorrelate.py --checkpoint data/checkpoint_<date>.jsonl
```

### Generating the case-study report

```bash
python3 scripts/generate_case_study.py
```

Finds the strongest real correlation example in your dataset (following the same reliability hierarchy used everywhere else in the project) and writes a ready-to-use Markdown report to `data/`.

## Running the dashboard

```bash
uvicorn webapp.main:app --reload --port 8000
```

Open `http://localhost:8000`. It needs Elasticsearch and Neo4j running with indexed data (see [Running a scan](#running-a-scan)) to show results — if either service is unavailable, the UI reports it explicitly instead of failing silently.

Free-text search combines two strategies, each where it fits: fuzzy matching (typo-tolerant, whole-token) on natural-language fields (HTTP title, server header), and real substring matching (`*term*`, case-insensitive) on identifier-style fields — address, technology, and the filename of every linked JS/CSS/favicon/document artifact. The latter matters because a linked resource's *filename* can carry real signal on its own (e.g. a leaked document called `DrugUsersBible.pdf`) that its hash alone doesn't, and because fuzzy matching alone does not do substring matching — searching `DrugUsersBible` would not have found `DrugUsersBible.pdf` without it. If you added this after indexing an older dataset, Elasticsearch won't pick up new fields on an index it already created (mappings for genuinely new fields are set once); delete the index and reindex from the checkpoint:
```bash
curl -X DELETE http://localhost:9200/onion_infra_discovery
python3 scripts/recorrelate.py --checkpoint data/checkpoint_<date>.jsonl
```

The header shows the project's identity as "Mycelium" (the branch-growing icon animates once on load), with "Onion Infrastructure Discovery" underneath as the underlying TFM's formal name.

## Optional: jurisdiction hint map

The dashboard's landing tab opens with a stylized world map (toggleable, state remembered across visits) plotting domains for which a **weak jurisdiction hint** could be derived from data already collected during the scan — never from the domain's real network location, which Tor makes fundamentally undeterminable by design. The hint comes from something the operator leaked unintentionally:

1. The `C=` (country) field of a TLS certificate's subject or issuer — a formal X.509 field, the more reliable of the two sources.
2. A small set of jurisdiction-revealing keywords in the HTTP title (e.g. a self-signed certificate literally naming a national police department, or a title in a government agency's own language) — weaker, used only when no certificate hint is available.

This requires **no rescanning and no LLM call**: both data sources are already stored in the checkpoint. To compute it:

```bash
python3 scripts/backfill_jurisdiction.py --checkpoint data/checkpoint_<date>.jsonl
```

This is the lightest backfill script in the project — pure local computation, no Tor, no Ollama, runs in seconds over thousands of domains, with none of the resource concerns documented in [Troubleshooting](#troubleshooting-the-llm-backfill-scripts) for the LLM scripts.

Hovering a point shows the domain's title, category (if resolved), and which source the hint came from; clicking it opens the same detail view used everywhere else in the dashboard. Domains that both have a jurisdiction hint *and* a confirmed infrastructure relation to another geolocated domain are connected with an animated line.

## Running the tests

```bash
python3 -m pytest tests/ -v
```

253 tests, no network or Docker services required — everything is exercised against fakes/doubles.

## Optional: local LLM content summaries

Each domain can optionally get a short, plain-language summary of its page content, generated by a small model running entirely on your own machine via [Ollama](https://ollama.com) — nothing is sent to any external API, which matters given the content being summarized. This is off by default (`config.ENABLE_LLM_SUMMARY = False`) and lives entirely outside the main scan path, so it never affects scan performance unless you explicitly opt in.

1. Install Ollama and pull a small model:
   ```bash
   ollama pull qwen2.5:1.5b
   ```
2. Set `ENABLE_LLM_SUMMARY = True` in `config.py`.
3. Run the backfill on an existing checkpoint:
   ```bash
   python3 scripts/backfill_summaries.py --checkpoint data/checkpoint_<date>.jsonl
   ```

The script re-fetches each domain's content (never persisted elsewhere), converts it to plain text, and summarizes it — caching by a hash of the extracted text so that domains sharing an identical page (a common template) only cost one real model call, and backing off automatically if Ollama stops responding partway through a large run. It is fully idempotent: rerunning it only processes domains that don't have a summary yet.

### Service-type classification (built on top of the summaries)

Once summaries exist, each domain can also get a coarse category (`marketplace`, `foro`, `panel_administracion`, `exchange_cripto`, `mensajeria`, `blog_personal`, `servicio_tecnico`, `directorio_enlaces`, `sin_contenido`, `otro` — see `config.LLM_CATEGORY_CHOICES`), using a *closed* classification prompt rather than open-ended generation — considerably more reliable for a small model. This is a separate, independent step:

1. Set `ENABLE_LLM_CATEGORY = True` in `config.py`.
2. Run:
   ```bash
   python3 scripts/backfill_categories.py --checkpoint data/checkpoint_<date>.jsonl
   ```

Unlike the summary backfill, this script classifies from the **already-generated summary text**, not the raw page — it never touches Tor at all, only Ollama, so it's considerably faster and lighter. It only processes domains that already have a summary but no category yet.

Both scripts share the same resilience patterns as the rest of the pipeline: a resumable/idempotent checkpoint, a circuit breaker that backs off after repeated Ollama failures, a progress bar with a live ETA (`src/progress_bar.py`, no new dependency), and — since sustained CPU/RAM load from running Tor + Neo4j + Elasticsearch + Ollama for hours in parallel has been observed to trigger a full machine shutdown on modest hardware — a deliberate pause (`config.LLM_SUMMARY_DELAY_SECONDS`) after every real model call, plus an optional `--limit N` flag to process the dataset in small, controlled batches instead of one long unattended run.

### Narrower scope: only domains with a confirmed relation

Running either backfill over an entire large dataset can take hours and repeatedly stresses modest hardware. `scripts/backfill_llm_related_domains.py` does both the summary and the category in one pass, but **only** for domains that are part of at least one confirmed infrastructure relation (the same `has_relations` set already used elsewhere in the dashboard) — in practice a much smaller, much faster subset, and arguably the only part of the dataset worth showing off in a demo anyway: an isolated domain with no correlations is not the story this tool tells.

```bash
python3 scripts/backfill_llm_related_domains.py --checkpoint data/checkpoint_<date>.jsonl
```

## Troubleshooting the LLM backfill scripts

Real problems hit while running the summary/category backfills on modest local hardware (Tor + Neo4j + Elasticsearch + Ollama running in parallel for a long time), and how each was solved. Documented here as concrete cases rather than general advice, since these are the exact failures encountered — not hypothetical ones.

**Case: the machine powers off completely while a backfill script is running (not just slow — a full shutdown), even with a small `--limit`.**
This is a hardware protection mechanism reacting to sustained or spiking resource load, not a bug that produces wrong output — nothing is corrupted, and the checkpoint already has everything processed up to that point (both backfill scripts append to the checkpoint after every domain, so nothing is lost). Try, in order:
1. Stop Neo4j and Elasticsearch before running the backfill — they are only needed for the final reload step, never during the actual summarization/classification loop. Use `--skip-reload` and run `scripts/recorrelate.py` afterwards instead:
   ```bash
   docker compose stop neo4j elasticsearch
   python3 scripts/backfill_summaries.py --checkpoint data/checkpoint_<date>.jsonl --skip-reload
   # later, once you're done and want it reflected in the dashboard:
   docker compose start neo4j elasticsearch
   python3 scripts/recorrelate.py --checkpoint data/checkpoint_<date>.jsonl
   ```
2. Force Ollama to CPU-only, in case it's trying to use an integrated/unstable GPU: set the system environment variable `OLLAMA_GPU_LAYERS=0` (Windows: Settings → Advanced system settings → Environment Variables), then fully restart Ollama (quitting and reopening isn't always enough — a full reboot may be needed for the variable to actually take effect). Verify with `ollama ps` while a model is loaded: it should say `100% CPU`, not `GPU`.
3. Use `scripts/backfill_llm_related_domains.py` instead of processing the whole dataset — it only touches domains that are part of a confirmed infrastructure relation, which in practice is a much smaller, much faster subset (and arguably the only part worth summarizing for a demo anyway).
4. If it still happens, scale down with `--limit` and increase gradually (10, then 12, then 15...) rather than jumping straight to a large batch — both scripts are idempotent, so each rerun only processes what's still missing.

**Case: you want to confirm whether Ollama is actually using CPU or GPU.**
```bash
ollama run qwen2.5:1.5b "hello"
ollama ps
```
`ollama ps` only shows models currently loaded in memory (Ollama unloads them after a period of inactivity), so you need to catch it right after a real call.

**Case: `ollama ps` returns nothing.**
Not an error — it just means no model is currently loaded (nothing has been queried recently). Run a quick prompt first (see above), then check again immediately.

**Case: a backfill run finished (or was interrupted) while Neo4j/Elasticsearch were stopped, and the dashboard doesn't reflect the new summaries/categories.**
Nothing was lost — the checkpoint has it all. Start the databases and reload from the checkpoint without rescanning:
```bash
docker compose start neo4j elasticsearch
python3 scripts/recorrelate.py --checkpoint data/checkpoint_<date>.jsonl
```

**Case: a scan/backfill log line shows a much larger "pending" count than you expect right before a `--limit` cuts it down.**
This is expected, not a bug: the log first reports the true total pending count, then immediately states how many the current run will actually process given `--limit`. Only the second number bounds the loop.

**Case: `--limit N` keeps reporting `summarized: 0` run after run, even though the machine isn't struggling.**
Two independent causes were found for this, both now fixed:
1. A domain whose page has genuinely insufficient content to summarize used to be left with no summary at all, which meant every rerun re-attempted it from scratch forever, silently eating into the `--limit` budget without any real progress. Both backfill scripts now write a sentinel value (`"Sin contenido suficiente para resumir."`) for these domains so they count as resolved and are never retried — a fetch *failure* (network/Tor issue), by contrast, is deliberately left retryable, since that can be transient.
2. Turning on `ENABLE_LLM_CATEGORY` after already having summarized some domains makes all of them newly "pending" again (they now need a category too) — this one-time backlog can dominate a run's `--limit` budget before any brand-new domain gets touched. It's not a bug, just something to expect the first time you enable categorization; it clears itself after a run or two.

**Case: you suspect one specific domain is causing the crash and want to test it in isolation.**
```bash
python3 scripts/backfill_llm_related_domains.py --checkpoint data/checkpoint_<date>.jsonl --address <the-address>.onion --skip-reload
```
This bypasses the relation filter and the pending-list logic entirely and force-processes only that one domain — a clean way to confirm or rule out a specific "poison pill" domain without risking the rest of a batch. In practice, this pointed away from any single domain and towards cumulative load during long, mostly-real (fetch + LLM) runs, rather than a domain-specific trigger.

**Case: after `docker compose stop`/`start` (not `down`/`up`) a container is missing its published port — e.g. `docker ps` shows `9200/tcp` instead of `0.0.0.0:9200->9200/tcp` for Elasticsearch, and the dashboard's Elasticsearch-backed sections fail with a connection error.**
`docker compose start` reuses a container exactly as it was originally created and does **not** re-read the current `docker-compose.yml` — if that container's port mapping was ever wrong at creation time, restarting it keeps reusing that same stale definition indefinitely. Force a real recreation from the current file instead:
```bash
docker compose down
docker compose up -d
```
Data is preserved (it lives in the named volumes, not in the container itself).

**Case: after that, `docker start` (or `docker compose up`) for Elasticsearch fails with `ports are not available: ... bind: An attempt was made to access a socket in a way forbidden by its access permissions` (Windows).**
This is a Windows/WSL2 networking issue, unrelated to the project itself — Windows can end up reserving a port range that includes 9200 for its own internal use, blocking anything else (including Docker) from binding to it. Quitting and restarting Docker Desktop entirely (not just the containers) resolves it in practice, since it restarts Docker's internal WSL2 networking. If that doesn't help, `netsh interface ipv4 show excludedportrange protocol=tcp` shows whether 9200 falls inside a reserved range, and restarting Windows' `winnat` service (`net stop winnat` / `net start winnat`, as Administrator) is the next thing to try.

## Safety & ethics

- **Mandatory safe-mode**: every domain is checked, hash-by-hash, against the official [Ahmia](https://ahmia.fi/) blocklist *before* it is fetched, enumerated, or indexed. `SAFE_MODE` is a hardcoded constant in `config.py`, deliberately **not** an environment variable — a misconfigured deployment can never accidentally disable it, since disabling it requires an explicit, reviewable code change.
- **Raw page content is never persisted.** Only derived artifacts (hashes, fingerprints, extracted metadata) are stored — never the HTML itself, and never images or audio.
- **HTML sub-resource hashing is scoped to same-origin only.** Linked JavaScript/CSS/favicon/document resources are only fetched if hosted on the *same* onion domain as the page that links them; external links are never followed.
- **No credentials in source control.** Local development credentials are read from environment variables (`.env`, gitignored) with safe defaults for local-only use.

## Known limitations

- **Single seed source.** Only Ahmia is currently implemented; adapters for additional discovery sources (Tor66, etc.) are a natural next step.
- **Content-similarity comparison is O(n²)** and is skipped above `config.CONTENT_SIMILARITY_MAX_ITEMS` (3000 by default) to avoid runaway comparison time on large datasets; exact-match correlations (certificate, SSH key, JARM, PGP, crypto address, HTML artifacts) remain O(n) via star-topology grouping and are always computed regardless of dataset size.
- **Very large "generic artifact" groups are flagged, not hidden.** A widely reused default certificate or a common JavaScript library (e.g. jQuery) can be "shared" by hundreds of unrelated domains — this is a weak/non-distinctive signal, not evidence of a common operator. The pipeline logs a warning for groups above 50 members, and the dashboard's 3D view caps rendering at 80 nodes per relationship type for performance, but the underlying correlation is still recorded. Every relation shown in the dashboard — compact panel and the 3D hover card — now also displays how many domains in total share that value (`group_size`, same 50-domain threshold, flagged visually when exceeded), so a specific relation's real strength is visible where you're actually looking at it, not only in a log line from scan time.
- **JARM implementation fidelity**: this reuses the official `pyJARM` packet/hash construction over a custom Tor-routed transport. It guarantees internal determinism and consistency (same real configuration → same hash within this dataset), not byte-for-byte compatibility with external public JARM hash databases.
- **LLM summaries/categories are a deliberately separate, manual step.** `run_batch.py` never imports or calls anything LLM-related, by design — running a fresh scan never touches Ollama, regardless of the `ENABLE_LLM_*` flags. This was a conscious choice (see [Troubleshooting](#troubleshooting-the-llm-backfill-scripts)) given the very different resource profile of Tor+Neo4j+Elasticsearch+Ollama running together for hours; it also means every new scan needs its own explicit backfill run afterwards.
- **Sustained real (fetch + LLM) backfill work has a hardware ceiling that isn't fully solved, only mitigated.** On modest local hardware, running the summary backfill continuously for a long stretch can trigger a full machine shutdown; this was confirmed to be about cumulative load rather than any single problematic domain (see the isolated `--address` test in Troubleshooting). The practical approach is processing in moderate, incrementally-sized batches rather than one long unattended run.
- See [`docs/DECISIONS.md`](docs/DECISIONS.md) for the full chronological log of bugs found, scaling issues, and the reasoning behind every non-obvious design choice in the project.

## Further reading

- [`docs/DECISIONS.md`](docs/DECISIONS.md) — detailed engineering log (Spanish), including the reliability hierarchy used for correlation, the combinatorial-explosion bug and its fix, and the design rationale for every extraction module.
