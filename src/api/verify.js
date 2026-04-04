import express from 'express';
import * as snarkjs from 'snarkjs';
import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { errorPayload, logError, logInfo, withRequest } from '../utils/logger.js';
import { hashName } from '../utils/identity.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SUPPORTED_PUBLIC_SIGNAL_COUNTS = new Set([6]);
const MAX_QR_AGE_DAYS = Number(process.env.MAX_QR_AGE_DAYS || 365);
const MAX_QR_FUTURE_SKEW_SECONDS = Number(process.env.MAX_QR_FUTURE_SKEW_SECONDS || 600);

export const verifyRouter = express.Router();

function evaluateTimestampFreshness(timestampSeconds) {
  if (!Number.isFinite(timestampSeconds) || timestampSeconds <= 0) {
    return { isFresh: false, isStale: true, reason: 'invalid_timestamp', ageDays: null };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (timestampSeconds > nowSeconds + MAX_QR_FUTURE_SKEW_SECONDS) {
    return { isFresh: false, isStale: true, reason: 'timestamp_in_future', ageDays: 0 };
  }

  const ageDays = (nowSeconds - timestampSeconds) / 86400;
  const isFresh = ageDays <= MAX_QR_AGE_DAYS;
  return {
    isFresh,
    isStale: !isFresh,
    reason: isFresh ? 'fresh' : 'stale',
    ageDays: Math.max(0, Math.floor(ageDays)),
  };
}

// POST /api/verify
// Verify a ZK proof
verifyRouter.post('/', async (req, res) => {
  try {
    const { proof, publicSignals } = req.body;
    logInfo('verify.request', withRequest({
      publicSignalsCount: Array.isArray(publicSignals) ? publicSignals.length : null,
      hasProof: Boolean(proof),
    }, req));

    if (!proof || !publicSignals) {
      logInfo('verify.invalid_request', withRequest({ reason: 'missing_fields' }, req));
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Please provide both proof and publicSignals',
        requestId: req.requestId,
      });
    }

    if (!Array.isArray(publicSignals) || !SUPPORTED_PUBLIC_SIGNAL_COUNTS.has(publicSignals.length)) {
      logInfo('verify.invalid_request', withRequest({
        reason: 'unsupported_signal_count',
        publicSignalsCount: Array.isArray(publicSignals) ? publicSignals.length : null,
      }, req));
      return res.status(400).json({
        error: 'Invalid public signals',
        message: 'publicSignals must be an array of length 6: [pubkeyHash, timestamp, ageAboveMin, minAgeUsed, signalHash, nameHash]',
        requestId: req.requestId,
      });
    }

    const startTime = Date.now();

    // Load verification key
    const vkeyPath = path.join(__dirname, '../../build/verification_key.json');
    const vKeyData = await readFile(vkeyPath, 'utf8');
    const vKey = JSON.parse(vKeyData);

    // Verify the proof
    const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);

    const duration = Date.now() - startTime;
    // Parse public signals to extract claims
    const claims = parsePublicSignals(publicSignals);
    const freshness = evaluateTimestampFreshness(claims?.timestamp);

    const eligible = Boolean(
      isValid &&
      claims &&
      claims.ageAboveMin &&
      freshness.isFresh
    );

    logInfo('verify.success', withRequest({
      durationMs: duration,
      valid: isValid,
      eligible,
      minAgeUsed: claims?.minAgeUsed,
      timestamp: claims?.timestamp,
      timestampAgeDays: freshness.ageDays,
      timestampFresh: freshness.isFresh,
      timestampFreshnessReason: freshness.reason,
    }, req));

    res.json({
      success: true,
      valid: isValid,
      eligible,
      claims: {
        ...claims,
        timestampAgeDays: freshness.ageDays,
        timestampFresh: freshness.isFresh,
        timestampFreshnessReason: freshness.reason,
      },
      metadata: {
        verificationTime: duration,
        maxQrAgeDays: MAX_QR_AGE_DAYS,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    logError('verify.failed', withRequest({
      error: errorPayload(error, process.env.NODE_ENV !== 'production'),
    }, req));
    res.status(500).json({
      error: 'Verification failed',
      message: error.message,
      details: process.env.NODE_ENV === 'production' ? undefined : error.stack,
      requestId: req.requestId,
    });
  }
});

// POST /api/verify/hash-name
// Compute circuit-compatible Poseidon hash of an expected name.
verifyRouter.post('/hash-name', async (req, res) => {
  try {
    const rawName = typeof req.body?.name === 'string' ? req.body.name : '';
    if (!rawName.trim()) {
      return res.status(400).json({
        error: 'Missing name',
        message: 'Please provide a non-empty name string',
        requestId: req.requestId,
      });
    }

    const nameHash = await hashName(rawName);
    res.json({ success: true, nameHash });
  } catch (error) {
    logError('verify.hash_name.failed', withRequest({
      error: errorPayload(error, process.env.NODE_ENV !== 'production'),
    }, req));
    res.status(500).json({
      error: 'Failed to hash name',
      message: error.message,
      requestId: req.requestId,
    });
  }
});

// Helper function to parse public signals into human-readable claims
function parsePublicSignals(publicSignals) {
  if (!Array.isArray(publicSignals) || !SUPPORTED_PUBLIC_SIGNAL_COUNTS.has(publicSignals.length)) {
    return null;
  }

  return {
    pubkeyHash: publicSignals[0],
    timestamp: parseInt(publicSignals[1], 10),
    ageAboveMin: parseInt(publicSignals[2], 10) === 1,
    minAgeUsed: parseInt(publicSignals[3], 10),
    signalHash: publicSignals[4],
    nameHash: publicSignals[5],
  };
}

// GET /api/verify/status
// Get verifier status
verifyRouter.get('/status', async (req, res) => {
  try {
    logInfo('verify.status.request', withRequest({}, req));
    const vkeyPath = path.join(__dirname, '../../build/verification_key.json');
    const vKeyData = await readFile(vkeyPath, 'utf8');
    const vKey = JSON.parse(vKeyData);

    res.json({
      status: 'ready',
      verificationKeyLoaded: true,
      protocol: vKey.protocol || 'groth16',
      curve: vKey.curve || 'bn128'
    });
  } catch (error) {
    logError('verify.status.failed', withRequest({
      error: errorPayload(error, process.env.NODE_ENV !== 'production'),
    }, req));
    res.status(500).json({
      status: 'error',
      error: error.message,
      requestId: req.requestId,
    });
  }
});
