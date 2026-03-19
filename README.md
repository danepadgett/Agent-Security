# Agent-Security

A local, AI-assisted endpoint security platform built in Rust, designed to evolve into a consumer-grade alternative to tools like CrowdStrike and SentinelOne.

---

## Overview

Agent-Security is an experimental cybersecurity platform that monitors local system activity, detects suspicious behavior, correlates events into incidents, and automatically responds based on configurable policy.

The system is designed with a **deterministic-first architecture**, where reliable detection and response pipelines are built before introducing AI-assisted reasoning.

---

## What Exists Today

The platform currently consists of two main components:

### Core Agent (Rust)

The core agent is a local endpoint security engine that:

- monitors file system activity in key directories
- detects newly launched processes
- generates structured telemetry events
- evaluates detections based on rules and scoring
- aggregates detections into higher-level incidents
- triggers automated response actions based on thresholds

### Desktop App (Tauri + React)

A desktop interface (in development) that will allow users to:

- view alerts and incidents
- understand system behavior
- control response policies
- monitor security events in real time

---

## Current Capabilities

- file monitoring (Downloads, Desktop, Documents, etc.)
- process monitoring and detection of new processes
- rule-based detection engine
- incident aggregation pipeline
- structured JSONL logging
- configurable response policy
- optional automated response:
  - process termination
  - file quarantine
- simulation mode for safe testing

---

## Architecture

The system is being built in layers:

### 1. Telemetry Collection
Collects raw events from the system:
- file creation / modification
- process execution

### 2. Detection Engine
Applies deterministic logic:
- suspicious paths
- execution patterns
- command features
- heuristic scoring

### 3. Correlation Layer
Groups detections into incidents:
- connects related behaviors
- builds execution context
- reduces noise

### 4. Response Layer
Executes actions when thresholds are exceeded:
- kill process
- quarantine file
- log incident

### 5. (Future) Intelligence Layer
Will introduce AI-assisted reasoning to:
- explain why something is malicious
- reduce false positives
- guide user decisions

---

## Repository Structure

```text
Agent-Security/
├── agents/
│   └── core-agent/          # Rust endpoint detection + response engine
├── apps/
│   └── desktop/             # Tauri + React desktop UI
├── runtime/
│   └── logs/                # JSONL telemetry output
├── docs/                    # Architecture + design docs (planned)
└── README.md

## Additional Documentation

- [`docs/repo-map.md`](docs/repo-map.md) — repository structure and file guide
- [`docs/architecture.md`](docs/architecture.md) — platform architecture
- [`docs/detection-model.md`](docs/detection-model.md) — detection philosophy and model
- [`docs/response-model.md`](docs/response-model.md) — response logic and guardrails
- [`docs/roadmap.md`](docs/roadmap.md) — current priorities and long-term direction