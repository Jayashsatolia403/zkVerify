import express from 'express';
import * as snarkjs from 'snarkjs';
import fs from 'fs';
import { promises as fsp } from 'fs';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { errorPayload, logError, logInfo, logWarn, withRequest } from '../utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TEST_CERTIFICATE_PATH = path.join(
  __dirname,
  '../../references/anon-aadhaar/packages/circuits/assets/testCertificate.pem'
);
const GENERATED_WRAPPER_PATH = path.join(__dirname, '../../build/aadhaar-age-verifier.circom');
const DEFAULT_MAX_DATA_LENGTH = 1280;
const WASM_PATH = path.join(__dirname, '../../build/aadhaar-age-verifier_js/aadhaar-age-verifier.wasm');
const ZKEY_PATH = path.join(__dirname, '../../build/aadhaar-age-verifier_final.zkey');
const ARTIFACT_CACHE_ENABLED = process.env.PROOF_ARTIFACT_CACHE !== 'false';

export const proofRouter = express.Router();

const proofArtifactsCache = {
  wasmBuffer: null,
  zkeyBuffer: null,
  loadedAt: null,
};

let artifactLoadPromise = null;

function isBufferInputCompatibilityError(error) {
  const message = error?.message || '';
  return (
    error instanceof TypeError ||
    message.includes('path must be of type string') ||
    message.includes('ENOENT')
  );
}

async function loadArtifactsFromDisk() {
  const readStart = process.hrtime.bigint();
  const [wasmBuffer, zkeyBuffer] = await Promise.all([
    fsp.readFile(WASM_PATH),
    fsp.readFile(ZKEY_PATH),
  ]);
  const readMs = Number(process.hrtime.bigint() - readStart) / 1e6;

  return {
    wasmBuffer,
    zkeyBuffer,
    readMs,
  };
}

async function getProvingArtifacts() {
  if (!ARTIFACT_CACHE_ENABLED) {
    const loaded = await loadArtifactsFromDisk();
    return {
      wasm: loaded.wasmBuffer,
      zkey: loaded.zkeyBuffer,
      cacheHit: false,
      loadMs: loaded.readMs,
      wasmBytes: loaded.wasmBuffer.length,
      zkeyBytes: loaded.zkeyBuffer.length,
    };
  }

  if (proofArtifactsCache.wasmBuffer && proofArtifactsCache.zkeyBuffer) {
    return {
      wasm: proofArtifactsCache.wasmBuffer,
      zkey: proofArtifactsCache.zkeyBuffer,
      cacheHit: true,
      loadMs: 0,
      wasmBytes: proofArtifactsCache.wasmBuffer.length,
      zkeyBytes: proofArtifactsCache.zkeyBuffer.length,
    };
  }

  if (!artifactLoadPromise) {
    artifactLoadPromise = (async () => {
      const loaded = await loadArtifactsFromDisk();
      proofArtifactsCache.wasmBuffer = loaded.wasmBuffer;
      proofArtifactsCache.zkeyBuffer = loaded.zkeyBuffer;
      proofArtifactsCache.loadedAt = new Date().toISOString();
      return loaded;
    })().finally(() => {
      artifactLoadPromise = null;
    });
  }

  const loaded = await artifactLoadPromise;
  return {
    wasm: loaded.wasmBuffer,
    zkey: loaded.zkeyBuffer,
    cacheHit: false,
    loadMs: loaded.readMs,
    wasmBytes: loaded.wasmBuffer.length,
    zkeyBytes: loaded.zkeyBuffer.length,
  };
}

export async function warmProofArtifacts() {
  const start = process.hrtime.bigint();
  const artifacts = await getProvingArtifacts();
  const durationMs = Number(process.hrtime.bigint() - start) / 1e6;

  logInfo('proof.artifacts.warm', {
    durationMs: Math.round(durationMs),
    cacheEnabled: ARTIFACT_CACHE_ENABLED,
    cacheHit: artifacts.cacheHit,
    wasmBytes: artifacts.wasmBytes,
    zkeyBytes: artifacts.zkeyBytes,
    loadedAt: proofArtifactsCache.loadedAt,
  });
}

function summarizeCircuitInputs(circuitInputs) {
  if (!circuitInputs || typeof circuitInputs !== 'object') return null;
  return {
    qrDataPaddedLength: Number(circuitInputs.qrDataPaddedLength || 0),
    qrDataPaddedCount: Array.isArray(circuitInputs.qrDataPadded) ? circuitInputs.qrDataPadded.length : 0,
    delimiterCount: Array.isArray(circuitInputs.delimiterIndices) ? circuitInputs.delimiterIndices.length : 0,
    signatureChunkCount: Array.isArray(circuitInputs.signature) ? circuitInputs.signature.length : 0,
    pubKeyChunkCount: Array.isArray(circuitInputs.pubKey) ? circuitInputs.pubKey.length : 0,
    minAge: Number(circuitInputs.minAge || 0),
    hasNameHash: typeof circuitInputs.nameHash === 'string' || typeof circuitInputs.nameHash === 'number',
  };
}

function splitToWords(number, wordsize, numberElement) {
  let t = number;
  const words = [];

  for (let i = 0n; i < numberElement; ++i) {
    words.push(`${t % (2n ** wordsize)}`);
    t = t / (2n ** wordsize);
  }

  if (t !== 0n) {
    throw new Error(`Number ${number} does not fit in ${(wordsize * numberElement).toString()} bits`);
  }

  return words;
}

function getTestCertificatePubKeyWords() {
  const certPem = fs.readFileSync(TEST_CERTIFICATE_PATH);
  const key = crypto.createPublicKey(certPem);
  const jwk = key.export({ format: 'jwk' });
  const modulus = Buffer.from(jwk.n, 'base64url').toString('hex');
  const pubKey = BigInt(`0x${modulus}`);

  return splitToWords(pubKey, 121n, 17n);
}

function getRuntimeMaxDataLength() {
  try {
    const wrapperSource = fs.readFileSync(GENERATED_WRAPPER_PATH, 'utf8');
    const match = wrapperSource.match(/AadhaarAgeVerifier\(\s*\d+\s*,\s*\d+\s*,\s*(\d+)\s*\)/);
    if (match && match[1]) {
      return parseInt(match[1], 10);
    }
  } catch (error) {
    // Fallback handled below.
  }

  return DEFAULT_MAX_DATA_LENGTH;
}

function getPerformanceHints(maxDataLength) {
  if (maxDataLength <= 1280) {
    return {
      profile: 'mobile',
      expectedProofMs: 45000,
      compileHint: 'npm run compile:circuit:mobile',
    };
  }

  if (maxDataLength <= 1536) {
    return {
      profile: 'balanced',
      expectedProofMs: 70000,
      compileHint: 'npm run compile:circuit:fast',
    };
  }

  return {
    profile: 'high-constraint',
    expectedProofMs: 95000,
    compileHint: 'npm run compile:circuit:dev',
  };
}

async function getArtifactVersion() {
  try {
    const [wasmStat, zkeyStat] = await Promise.all([
      fsp.stat(WASM_PATH),
      fsp.stat(ZKEY_PATH),
    ]);
    return `${wasmStat.mtimeMs}-${zkeyStat.mtimeMs}-${zkeyStat.size}`;
  } catch {
    return null;
  }
}

// POST /api/proof/generate
// Generate ZK proof from Aadhaar QR data
proofRouter.post('/generate', async (req, res) => {
  try {
    const routeStart = process.hrtime.bigint();
    const { circuitInputs } = req.body;
    logInfo('proof.generate.request', withRequest({
      circuitInputs: summarizeCircuitInputs(circuitInputs),
    }, req));

    if (!circuitInputs) {
      logInfo('proof.generate.invalid_request', withRequest({ reason: 'missing_circuit_inputs' }, req));
      return res.status(400).json({
        error: 'Missing circuit inputs',
        message: 'Please provide circuitInputs in request body',
        requestId: req.requestId,
      });
    }

    if (circuitInputs.nameHash === undefined || circuitInputs.nameHash === null || circuitInputs.nameHash === '') {
      return res.status(400).json({
        error: 'Missing nameHash',
        message: 'circuitInputs.nameHash is required for identity-bound proofs',
        requestId: req.requestId,
      });
    }

    const inputReadyAt = process.hrtime.bigint();

    logInfo('proof.generate.start', withRequest({
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      artifactCacheEnabled: ARTIFACT_CACHE_ENABLED,
    }, req));

    const artifactsStart = process.hrtime.bigint();
    const artifacts = await getProvingArtifacts();
    const artifactsEnd = process.hrtime.bigint();

    let proof;
    let publicSignals;
    let proveMode = 'buffer';

    const proveStart = process.hrtime.bigint();
    try {
      ({ proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs,
        artifacts.wasm,
        artifacts.zkey
      ));
    } catch (error) {
      if (!isBufferInputCompatibilityError(error)) {
        throw error;
      }

      proveMode = 'path-fallback';
      logWarn('proof.generate.buffer_mode_fallback', withRequest({
        message: error?.message || 'Unknown buffer mode error',
      }, req));

      ({ proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs,
        WASM_PATH,
        ZKEY_PATH
      ));
    }
    const proveEnd = process.hrtime.bigint();

    const totalDuration = Number(process.hrtime.bigint() - routeStart) / 1e6;
    const inputParseMs = Number(inputReadyAt - routeStart) / 1e6;
    const artifactFetchMs = Number(artifactsEnd - artifactsStart) / 1e6;
    const fullProveMs = Number(proveEnd - proveStart) / 1e6;

    logInfo('proof.generate.success', withRequest({
      durationMs: Math.round(totalDuration),
      inputParseMs: Math.round(inputParseMs),
      artifactFetchMs: Math.round(artifactFetchMs),
      artifactLoadMs: Math.round(artifacts.loadMs),
      artifactCacheHit: artifacts.cacheHit,
      fullProveMs: Math.round(fullProveMs),
      proveMode,
      publicSignalsCount: Array.isArray(publicSignals) ? publicSignals.length : 0,
      wasmBytes: artifacts.wasmBytes,
      zkeyBytes: artifacts.zkeyBytes,
    }, req));

    res.json({
      success: true,
      proof,
      publicSignals,
      metadata: {
        generationTime: Math.round(fullProveMs),
        totalDurationMs: Math.round(totalDuration),
        inputParseMs: Math.round(inputParseMs),
        artifactFetchMs: Math.round(artifactFetchMs),
        artifactLoadMs: Math.round(artifacts.loadMs),
        artifactCacheHit: artifacts.cacheHit,
        proveMode,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    const message = error?.message || 'Unknown proof generation error';
    const isSchemaMismatch =
      message.includes('Too many values for input signal') ||
      message.includes('Not all inputs have been set');
    const isNameHashMismatch =
      message.includes('AadhaarAgeVerifier') && message.includes('line: 71');

    logError('proof.generate.failed', withRequest({
      schemaMismatch: isSchemaMismatch,
      error: errorPayload(error, process.env.NODE_ENV !== 'production'),
    }, req));

    if (isSchemaMismatch) {
      return res.status(400).json({
        error: 'Circuit input schema mismatch',
        message,
        hint: 'Compiled artifacts are out of sync with current circuit/input schema. Re-run compile + ceremony and restart server.',
        fixCommands: [
          'npm run compile:circuit:mobile',
          'npm run setup:ceremony',
          'npm start'
        ],
        requestId: req.requestId,
      });
    }

    if (isNameHashMismatch) {
      return res.status(400).json({
        error: 'Name hash mismatch',
        message,
        hint: 'Expected name does not exactly match the Aadhaar name bytes in the signed QR payload.',
        remediation: [
          'Use exact casing and spacing from Aadhaar QR name field',
          'Avoid trimming/normalizing before hashing',
          'Recompute nameHash with POST /api/verify/hash-name using exact expected name'
        ],
        requestId: req.requestId,
      });
    }

    res.status(500).json({
      error: 'Proof generation failed',
      message,
      details: process.env.NODE_ENV === 'production' ? undefined : error.stack,
      requestId: req.requestId,
    });
  }
});

// GET /api/proof/key
// Return public key words matching scripts/generate-and-verify-proof.js (testCertificate.pem)
proofRouter.get('/key', async (req, res) => {
  try {
    logInfo('proof.key.request', withRequest({}, req));
    res.json({
      keySource: 'references/anon-aadhaar/packages/circuits/assets/testCertificate.pem',
      pubKeyWords: getTestCertificatePubKeyWords()
    });
  } catch (error) {
    logError('proof.key.failed', withRequest({
      error: errorPayload(error, process.env.NODE_ENV !== 'production'),
    }, req));
    res.status(500).json({
      error: 'Failed to load proof key',
      message: error.message,
      requestId: req.requestId,
    });
  }
});

// GET /api/proof/info
// Get circuit information
proofRouter.get('/info', async (req, res) => {
  try {
    const maxDataLength = getRuntimeMaxDataLength();
    const performanceHints = getPerformanceHints(maxDataLength);
    const artifactVersion = await getArtifactVersion();
    logInfo('proof.info.request', withRequest({
      maxDataLength,
      performanceProfile: performanceHints.profile,
    }, req));

    res.json({
      circuit: 'aadhaar-age-verifier',
      parameters: {
        n: 121,
        k: 17,
        maxDataLength
      },
      description: 'Zero-knowledge proof for Aadhaar age >= minAge verification',
      keySource: 'references/anon-aadhaar/packages/circuits/assets/testCertificate.pem',
      claimPolicy: 'age >= minAge && aadhaarNameHash == expectedNameHash',
      performanceHints,
      artifactCache: {
        enabled: ARTIFACT_CACHE_ENABLED,
        warmed: Boolean(proofArtifactsCache.loadedAt),
        loadedAt: proofArtifactsCache.loadedAt,
      },
      artifactVersion,
      publicInputs: ['signalHash', 'nameHash'],
      publicOutputs: [
        'pubkeyHash',
        'timestamp',
        'ageAboveMin',
        'minAgeUsed'
      ],
      publicSignalsSchema: [
        'pubkeyHash',
        'timestamp',
        'ageAboveMin',
        'minAgeUsed',
        'signalHash',
        'nameHash'
      ]
    });
  } catch (error) {
    logError('proof.info.failed', withRequest({
      error: errorPayload(error, process.env.NODE_ENV !== 'production'),
    }, req));
    res.status(500).json({ error: error.message, requestId: req.requestId });
  }
});
