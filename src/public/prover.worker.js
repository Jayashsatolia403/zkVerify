self.importScripts('/vendor/snarkjs/snarkjs.min.js');

const artifactCache = {
  wasmPath: null,
  zkeyPath: null,
  wasmBuffer: null,
  zkeyBuffer: null,
  loadingPromise: null,
};

function clearBufferArtifacts() {
  artifactCache.wasmPath = null;
  artifactCache.zkeyPath = null;
  artifactCache.wasmBuffer = null;
  artifactCache.zkeyBuffer = null;
  artifactCache.loadingPromise = null;
}

function post(type, payload) {
  self.postMessage({ type, payload });
}

async function preloadArtifacts(wasmPath, zkeyPath) {
  const cacheHit =
    artifactCache.wasmBuffer &&
    artifactCache.zkeyBuffer &&
    artifactCache.wasmPath === wasmPath &&
    artifactCache.zkeyPath === zkeyPath;

  if (cacheHit) {
    return { cacheHit: true, bytes: artifactCache.zkeyBuffer.byteLength + artifactCache.wasmBuffer.byteLength };
  }

  if (!artifactCache.loadingPromise) {
    artifactCache.loadingPromise = (async () => {
      const [wasmResponse, zkeyResponse] = await Promise.all([
        fetch(wasmPath, { cache: 'force-cache' }),
        fetch(zkeyPath, { cache: 'force-cache' }),
      ]);

      if (!wasmResponse.ok || !zkeyResponse.ok) {
        throw new Error('Failed to load proving artifacts in worker.');
      }

      const [wasmArrayBuffer, zkeyArrayBuffer] = await Promise.all([
        wasmResponse.arrayBuffer(),
        zkeyResponse.arrayBuffer(),
      ]);

      artifactCache.wasmPath = wasmPath;
      artifactCache.zkeyPath = zkeyPath;
      artifactCache.wasmBuffer = new Uint8Array(wasmArrayBuffer);
      artifactCache.zkeyBuffer = new Uint8Array(zkeyArrayBuffer);
    })().finally(() => {
      artifactCache.loadingPromise = null;
    });
  }

  await artifactCache.loadingPromise;
  return {
    cacheHit: false,
    bytes: artifactCache.zkeyBuffer.byteLength + artifactCache.wasmBuffer.byteLength,
  };
}

function normalizeArtifactStrategy(value) {
  return value === 'path' ? 'path' : 'buffer';
}

function normalizeCachePolicy(value) {
  return value === 'release' ? 'release' : 'retain';
}

self.onmessage = async (event) => {
  const { type, payload } = event.data || {};
  if (!type) return;

  try {
    const { requestId, circuitInputs, wasmPath, zkeyPath } = payload || {};
    const artifactStrategy = normalizeArtifactStrategy(payload?.artifactStrategy);
    const cachePolicy = normalizeCachePolicy(payload?.cachePolicy);

    if (!wasmPath || !zkeyPath) {
      throw new Error('Missing worker artifact paths.');
    }

    if (type === 'warmup') {
      const warmupStart = performance.now();
      if (artifactStrategy === 'path') {
        clearBufferArtifacts();
        post('ready', {
          requestId,
          cacheHit: false,
          bytes: 0,
          warmupMs: Math.round(performance.now() - warmupStart),
          proveMode: 'path',
        });
        return;
      }

      const preload = await preloadArtifacts(wasmPath, zkeyPath);
      post('ready', {
        requestId,
        cacheHit: preload.cacheHit,
        bytes: preload.bytes,
        warmupMs: Math.round(performance.now() - warmupStart),
        proveMode: 'buffer',
      });
      return;
    }

    if (type !== 'prove') return;

    post('phase', {
      requestId,
      message: 'Preparing proving artifacts...',
      spinning: true,
    });

    let preload = { cacheHit: false, bytes: 0 };
    let warmupMs = 0;

    if (artifactStrategy === 'buffer') {
      const warmupStart = performance.now();
      preload = await preloadArtifacts(wasmPath, zkeyPath);
      warmupMs = Math.round(performance.now() - warmupStart);
    } else {
      // Ensure we do not retain stale buffer copies when path mode is requested.
      clearBufferArtifacts();
    }

    post('phase', {
      requestId,
      message: 'Generating cryptographic proof...',
      spinning: true,
    });

    const proveStart = performance.now();
    const result = artifactStrategy === 'path'
      ? await self.snarkjs.groth16.fullProve(circuitInputs, wasmPath, zkeyPath)
      : await self.snarkjs.groth16.fullProve(
        circuitInputs,
        artifactCache.wasmBuffer,
        artifactCache.zkeyBuffer
      );
    const fullProveMs = Math.round(performance.now() - proveStart);

    if (cachePolicy === 'release') {
      clearBufferArtifacts();
    }

    post('phase', {
      requestId,
      message: 'Finalizing proof...',
      spinning: false,
    });

    post('result', {
      requestId,
      ...result,
      perf: {
        fullProveMs,
        warmupMs,
        cacheHit: preload.cacheHit,
        artifactBytes: preload.bytes,
        proveMode: artifactStrategy,
      },
    });
  } catch (error) {
    post('error', {
      requestId: payload?.requestId,
      message: error?.message || 'Unknown worker proving error',
    });
  }
};

