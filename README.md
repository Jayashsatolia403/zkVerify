# ZK-Verify

**Privacy-preserving identity verification for India using zero-knowledge proofs.**

ZK-Verify lets any developer verify identity claims against UIDAI-signed Aadhaar data — without ever seeing the underlying document. The verifier gets a cryptographic guarantee. Zero personal data is exposed, transmitted, or stored.

## The Problem

Every company doing KYC in India collects full Aadhaar documents — name, number, address, photo — and stores all of it. India's Digital Personal Data Protection Act (2023) mandates data minimization, but there's no technical infrastructure to verify identity claims without over-collecting data.

## The Solution

ZK-Verify uses zero-knowledge proofs to verify claims like "this person is over 18" against the Indian government's own digital signature on Aadhaar data. The proof is generated client-side. The verifier's API receives only the proof and a boolean result — never the document.

### How it works

1. User scans their Aadhaar QR code (present on every e-Aadhaar and Aadhaar letter)
2. The app extracts the digitally signed data from the QR payload
3. A ZK circuit verifies the UIDAI RSA-2048 signature **inside the proof** and checks the claim (e.g., age ≥ 18)
4. The proof is sent to the verifier's backend, which cryptographically validates it
5. The verifier receives: `{ verified: true, claim: "age_over_18" }` — nothing else

The Aadhaar document never leaves the user's device. The verifier never sees it. Mathematically guaranteed.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  User's Device                   │
│                                                   │
│  Aadhaar QR ──► Parse ──► ZK Circuit ──► Proof   │
│                          (RSA verify +            │
│                           age check)              │
└──────────────────────┬──────────────────────────┘
                       │ proof + public signals
                       ▼
┌──────────────────────────────────────────────────┐
│              ZK-Verify Backend                    │
│                                                    │
│  POST /verify ──► snarkjs verify ──► Receipt      │
│                                                    │
│  Returns: { verified, claim, proof_hash,           │
│             nullifier, timestamp }                 │
│                                                    │
│  Stores: verification receipt (no PII, ever)       │
└──────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Circuits | Circom 2.x + circomlib | ZK constraint system (RSA verification, age comparison) |
| Proving System | Groth16 via snarkjs | Proof generation and verification |
| Crypto Primitives | [anon-aadhaar](https://github.com/anon-aadhaar/anon-aadhaar) circuits | Audited RSA-2048 + SHA-256 verification in ZK |
| Prover Service | Node.js + Express | Server-side proof generation |
| Verification API | Python + FastAPI | Proof verification, receipts, rate limiting |
| Database | MongoDB | Verification receipt storage |
| Cache | Redis | Rate limiting, nonce management |
| Frontend | Next.js + Tailwind | Demo interface |

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Data forgery | UIDAI RSA-2048 signature verified inside the ZK circuit |
| Replay attacks | Nullifier derived from Aadhaar data + verifier-specific nonce |
| Stale data | Aadhaar XML timestamp exposed as public signal; verifier enforces freshness |
| Identity binding | Production roadmap: liveness check before proof generation |
| Circuit bugs | Built on audited anon-aadhaar primitives + exhaustive edge-case testing |

## Project Structure

```
zkverify/
├── circuits/           # Circom source files
│   ├── main.circom     # Top-level circuit
│   └── lib/            # RSA, SHA-256 from anon-aadhaar
├── prover-service/     # Node.js proof generation
├── backend/            # Python FastAPI verification API
├── lib/                # Shared TypeScript (QR parsing, input prep)
├── frontend/           # Next.js demo UI
├── scripts/            # Setup ceremony, test scripts
├── test/               # Sample QR data, expected outputs
└── docs/               # Architecture docs, threat model
```

## Status

🔨 **In active development.** Circuit integration in progress.

## Author

**Jayash** — Senior Backend Engineer. Previously Lead Engineer at 0Chain, where I architected tokenomics and storage smart contracts for a Layer 1 blockchain processing 210M+ transactions. Building at the intersection of cryptography and identity infrastructure.
