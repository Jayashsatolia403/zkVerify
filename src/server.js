import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { proofRouter, warmProofArtifacts } from './api/proof.js';
import { verifyRouter } from './api/verify.js';
import { errorPayload, logError, logInfo, logWarn, withRequest } from './utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

app.use((req, res, next) => {
  req.requestId = req.get('x-request-id') || randomUUID();
  res.setHeader('x-request-id', req.requestId);
  next();
});

app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  logInfo('http.request.start', withRequest({
    ip: req.ip,
    userAgent: req.get('user-agent') || null,
    contentLength: Number(req.get('content-length') || 0),
  }, req));

  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    logInfo('http.request.finish', withRequest({
      statusCode: res.statusCode,
      durationMs: Math.round(durationMs),
      responseBytes: Number(res.getHeader('content-length') || 0),
    }, req));
  });

  res.on('close', () => {
    if (!res.writableEnded) {
      const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
      logWarn('http.request.aborted', withRequest({
        durationMs: Math.round(durationMs),
      }, req));
    }
  });

  next();
});

// Enable cross-origin isolation so browser WASM provers can use SharedArrayBuffer.
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
});

// Static assets for in-browser proving demo
const immutableStaticOptions = {
  maxAge: '365d',
  immutable: true,
};

app.use('/build', express.static(path.join(rootDir, 'build'), immutableStaticOptions));
app.use('/vendor/snarkjs', express.static(path.join(rootDir, 'node_modules/snarkjs/build'), immutableStaticOptions));
app.use('/vendor/pako', express.static(path.join(rootDir, 'node_modules/pako/dist'), immutableStaticOptions));
app.use('/vendor/jsqr', express.static(path.join(rootDir, 'node_modules/jsqr/dist'), immutableStaticOptions));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/api/proof', proofRouter);
app.use('/api/verify', verifyRouter);

// Health check
app.get('/health', (req, res) => {
  logInfo('health.check', withRequest({}, req));
  res.json({ status: 'ok', service: 'zk-verify-api', timestamp: new Date().toISOString() });
});

// API info endpoint
app.get('/api', (req, res) => {
  logInfo('api.meta', withRequest({}, req));
  res.json({
    service: 'ZK-Verify API',
    version: '1.0.0',
    description: 'Zero-knowledge proof generation and verification for Aadhaar age verification',
    endpoints: {
      health: 'GET /health',
      generateProof: 'POST /api/proof/generate',
      verifyProof: 'POST /api/verify',
      hashName: 'POST /api/verify/hash-name'
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logError('http.unhandled_error', withRequest({
    statusCode: 500,
    error: errorPayload(err, process.env.NODE_ENV !== 'production'),
  }, req));
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
    requestId: req.requestId,
  });
});

// Start server
app.listen(PORT, () => {
  logInfo('server.start', {
    port: PORT,
    browserDemo: `http://localhost:${PORT}/`,
    health: `http://localhost:${PORT}/health`,
    api: `http://localhost:${PORT}/api`,
  });

  if (process.env.PROOF_PRELOAD_ON_START === 'true') {
    warmProofArtifacts().catch((error) => {
      logWarn('proof.artifacts.warm_failed', {
        message: error?.message || 'Unknown artifact preload error',
      });
    });
  }
});

export default app;
