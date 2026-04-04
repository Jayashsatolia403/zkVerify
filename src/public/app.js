const WASM_PATH = '/build/aadhaar-age-verifier_js/aadhaar-age-verifier.wasm';
const ZKEY_PATH = '/build/aadhaar-age-verifier_final.zkey';
const PROVER_WORKER_PATH = '/prover.worker.js';
const BENCHMARK_MODE = new URLSearchParams(window.location.search).has('bench');
const URL_PARAMS = new URLSearchParams(window.location.search);
const DEMO_PREFILL_ENABLED = URL_PARAMS.get('demoData') === '1';
const MOBILE_USER_AGENT = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
const LOW_MEMORY_DEVICE = typeof navigator.deviceMemory === 'number' && navigator.deviceMemory <= 4;
const LOW_MEMORY_MODE = MOBILE_USER_AGENT || LOW_MEMORY_DEVICE;
const PREFILLED_QR_DATA = `2033392736027927750686770405183106980748033161059348001786275141098427105637742690527448961782881224920221930305685083971227235291648426573377574535190688515300474376123764617357170759595986996351632260964561460796446934206632998318330615890467906544900323416288274077544798834827945273518907890134056663408457498149220646560908427622631121552463327220641056495734149331596605663419880024327529952805776229484872539344773551542527930454206149230418446838009640955253581582308163738359292154771776354803439886331423987585835418002817007147723942790493477741823105956684650728920054855369979501403182989043545012059885904312415146155727536171497773958527561648462850615582081012744232209829247674428945739038603114465731578848122965228599649250673553144291734427934358486849481700517409798051191954046039797815524206616487885236269587985660764763848990289575901032617984864038495654512163202073325775835161098950945095986307672792877003485974448066243692410378130206905263518566941316589921339457902398648056685783689515883825389538930392444552754323255888292843259929935531240023189701135672043440684029225028892729852024111140539636592512076818798731115303640874262161941336746702559798303894696206310098152885993245916901296127553051860774705912358516529986679206371284682668196209119484093863344441921268296558830301086745390562135486788362246790736741890928470905603759016635421989019230182672900661392772355886746207337556501355997683884924700191161771106261114852993808890259841119602004472806401956724089832714839934370707098881009522198302568294983837419724180110156262818715165261688266173631590007669622957439355328074277101071583447727166772549401485949880431299217219154233478623317457037448442501334875566729150533142466589749259652989173326476398452111177361008637329340122090253113762925790313201836512490743674390188295389301167352526490179256148585088312566171071840516029181532446662004755192112241898359477018477717078723995809081165623100425953536636082376583810308082754365919044557058051235194605281207907662983728550577822349455956273241778940015416957855469066595480043604017483369462015027933169415555283886918683477187924667355110722574508935810259063664643511024306440106531854176590416767722689709475550907700643643883385494768311273489203888879156656974599107338972371662953873032264240685269825257844847034746390879441950841976919040737802387370144351711301022218707459818888844513212070583026379838736441242105435626508117178901281805297392554624393137318161039647655363779939157981361815978094044868870068349860512540794873786773669137175811536090821860598087447403101338755173832479311654745194681390373092444387890552074173869473377687298785437445069256212000698603322255217949643711414248027720233796022265450054822318474210594876641453369925545244494913368517736599894820038643011612582209104404875343722255542122917841601911944584770194000864943382173223759979428634520538298532785965159393820204422777122517663110299290479177929397358990300352413696`;

const qrInputEl = document.getElementById('qrInput');
const expectedNameInputEl = document.getElementById('expectedNameInput');
const minAgeInputEl = document.getElementById('minAgeInput');
const generateBtnEl = document.getElementById('generateBtn');
const inputHintEl = document.getElementById('inputHint');
const cardEl = document.getElementById('verificationCard');
const inputStateEl = document.getElementById('inputState');
const provingStateEl = document.getElementById('provingState');
const resultStateEl = document.getElementById('resultState');
const errorStateEl = document.getElementById('errorState');
const pastePanelEl = document.getElementById('pastePanel');
const togglePasteBtnEl = document.getElementById('togglePasteBtn');
const agePillsEl = document.getElementById('agePills');
const customAgeToggleEl = document.getElementById('customAgeToggle');
const customAgePanelEl = document.getElementById('customAgePanel');
const provingMessageEl = document.getElementById('provingMessage');
const provingDetailEl = document.getElementById('provingDetail');
const progressRingWrapEl = document.querySelector('.progress-ring-wrap');
const progressRingBarEl = document.getElementById('progressRingBar');
const progressPercentEl = document.getElementById('progressPercent');
const elapsedTimeEl = document.getElementById('elapsedTime');
const resultHeadlineEl = document.getElementById('resultHeadline');
const revealedAgeRowEl = document.getElementById('revealedAgeRow');
const proofTimeValueEl = document.getElementById('proofTimeValue');
const proofSizeValueEl = document.getElementById('proofSizeValue');
const verifyTimeValueEl = document.getElementById('verifyTimeValue');
const proofHashValueEl = document.getElementById('proofHashValue');
const copyHashBtnEl = document.getElementById('copyHashBtn');
const verifyAgainBtnEl = document.getElementById('verifyAgainBtn');
const tryAgainBtnEl = document.getElementById('tryAgainBtn');
const errorMessageEl = document.getElementById('errorMessage');
const toastEl = document.getElementById('toast');
const scanQrBtnEl = document.getElementById('scanQrBtn');
const stopScanBtnEl = document.getElementById('stopScanBtn');
const scannerPanelEl = document.getElementById('scannerPanel');
const qrValidationEl = document.getElementById('qrValidation');
const provingModeEl = document.getElementById('provingMode');

const stageEls = {
  input: inputStateEl,
  proving: provingStateEl,
  result: resultStateEl,
  error: errorStateEl,
};

let proofKeyPromise;
let proofInfoPromise;
let artifactWarmupPromise;
let proofHashFull = '';
let toastTimerId;
let elapsedTimerId;
let elapsedStartedAt = 0;
let html5QrCode;
let scannerStream;
let scannerVideoEl;
let scannerCanvasEl;
let scannerCanvasCtx;
let scannerFrameRequest;
let timelineTimerId;
let timelineElapsedSeconds = 0;
let timelineProgressValue = 0;
let activeProvingMode = 'local';
let proverWorker;
let workerRequestId = 0;
let artifactVersionToken = '';

const EXPECTED_DURATION_MS = 70000;
const PRE_COMPLETE_MAX = 90;
const PROOF_HISTORY_STORAGE_KEY = 'zkverify.proofHistoryMs.v1';
const BROWSER_ISOLATED = window.crossOriginIsolated === true;
const AVAILABLE_CORES = Number(navigator.hardwareConcurrency || 1);
const ARTIFACT_MODE_OVERRIDE = URL_PARAMS.get('artifactMode');
const LOCAL_ARTIFACT_MODE = ARTIFACT_MODE_OVERRIDE === 'buffer' || ARTIFACT_MODE_OVERRIDE === 'path'
  ? ARTIFACT_MODE_OVERRIDE
  : (LOW_MEMORY_MODE ? 'path' : 'buffer');
const ARTIFACT_CACHE_OVERRIDE = URL_PARAMS.get('artifactCache');
const LOCAL_ARTIFACT_CACHE_POLICY = ARTIFACT_CACHE_OVERRIDE === 'retain' || ARTIFACT_CACHE_OVERRIDE === 'release'
  ? ARTIFACT_CACHE_OVERRIDE
  : (LOW_MEMORY_MODE ? 'release' : 'retain');

let expectedDurationMs = EXPECTED_DURATION_MS;

function logBench(event, payload) {
  if (!BENCHMARK_MODE) return;
  console.log('[bench]', JSON.stringify({ event, ...payload }));
}

function loadProofHistory() {
  try {
    const raw = window.localStorage.getItem(PROOF_HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((value) => Number.isFinite(value) && value > 0);
  } catch (error) {
    return [];
  }
}

function saveProofHistory(values) {
  try {
    window.localStorage.setItem(PROOF_HISTORY_STORAGE_KEY, JSON.stringify(values.slice(-8)));
  } catch (error) {
    // Ignore storage failures (e.g., private mode).
  }
}

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[middle];
  return (sorted[middle - 1] + sorted[middle]) / 2;
}

function pickExpectedDurationMs(proofInfo) {
  const history = loadProofHistory();
  const historyMedian = median(history);
  const profileHint = Number(proofInfo?.performanceHints?.expectedProofMs);

  if (historyMedian > 0) {
    return Math.max(30000, Math.min(120000, Math.round(historyMedian * 1.15)));
  }

  if (Number.isFinite(profileHint) && profileHint > 0) {
    return Math.round(profileHint);
  }

  return EXPECTED_DURATION_MS;
}

function recordProofDuration(durationMs) {
  if (!Number.isFinite(durationMs) || durationMs <= 0) return;
  const history = loadProofHistory();
  history.push(Math.round(durationMs));
  saveProofHistory(history);
}

function setCardState(state) {
  cardEl.dataset.state = state;
  for (const [name, element] of Object.entries(stageEls)) {
    const isActive = name === state;
    element.hidden = !isActive;
    element.style.display = isActive ? 'flex' : 'none';
  }
}

function setQrValidation(message) {
  qrInputEl.classList.add('input-invalid');
  qrValidationEl.textContent = message;
  qrValidationEl.hidden = false;
  setPastePanelVisible(true);
}

function getSelectedProvingMode() {
  return provingModeEl?.value === 'server' ? 'server' : 'local';
}

function updateModeHint() {
  if (getSelectedProvingMode() === 'server') {
    inputHintEl.textContent = 'Server-side mode sends circuit inputs to the backend prover.';
  } else {
    if (!BROWSER_ISOLATED) {
      inputHintEl.textContent = 'Local proving is slower without cross-origin isolation. Consider server-side mode for speed.';
    } else {
      inputHintEl.textContent = 'Your data is processed entirely in your browser.';
    }
  }
}

function clearQrValidation() {
  qrInputEl.classList.remove('input-invalid');
  qrValidationEl.hidden = true;
}

function setPastePanelVisible(isVisible) {
  pastePanelEl.hidden = !isVisible;
  togglePasteBtnEl.textContent = isVisible ? 'Hide pasted data' : 'Paste QR Data';
}

function showToast(message) {
  clearTimeout(toastTimerId);
  toastEl.textContent = message;
  toastEl.hidden = false;
  toastTimerId = window.setTimeout(() => {
    toastEl.hidden = true;
  }, 1800);
}

function setAge(minAge, useCustomInput) {
  minAgeInputEl.value = String(minAge);
  for (const pill of agePillsEl.querySelectorAll('.age-pill')) {
    const age = pill.dataset.age;
    const active = age === 'custom' ? useCustomInput : Number(age) === Number(minAge) && !useCustomInput;
    pill.classList.toggle('is-active', active);
  }
  customAgePanelEl.hidden = !useCustomInput;
}

function formatMs(value) {
  if (value >= 1000) return `${(value / 1000).toFixed(1)}s`;
  return `${Math.round(value)}ms`;
}

function getTimelineStatus(elapsedSeconds) {
  if (activeProvingMode === 'server') {
    if (elapsedSeconds < 2) {
      return {
        message: 'Preparing server-side proving request...',
        detail: 'Packaging circuit inputs for secure transmission.',
      };
    }

    if (elapsedSeconds < 8) {
      return {
        message: 'Sending proving request to server...',
        detail: 'Derived inputs are sent to the backend prover.',
      };
    }

    if (elapsedSeconds < 60) {
      return {
        message: 'Generating ZK proof on server...',
        detail: 'Server prover is computing witness and proof.',
      };
    }

    return {
      message: 'Almost there - finalizing proof...',
      detail: 'Waiting for proof response from server.',
    };
  }

  if (elapsedSeconds < 2) {
    return {
      message: 'Loading proving key...',
      detail: 'Initializing proving artifacts in this browser.',
    };
  }

  if (elapsedSeconds < 5) {
    return {
      message: 'Decompressing Aadhaar QR data...',
      detail: 'Parsing QR data locally on your device.',
    };
  }

  if (elapsedSeconds < 10) {
    return {
      message: 'Computing witness for ZK circuit...',
      detail: 'Preparing private witness values.',
    };
  }

  if (elapsedSeconds < 60) {
    const longPhaseDetails = [
      'Your data stays on your device throughout this process.',
      'Computing multi-scalar multiplication on elliptic curves.',
      'Building polynomial commitments.',
      'Verifying constraint satisfaction.',
    ];
    const index = Math.floor((elapsedSeconds - 10) / 10) % longPhaseDetails.length;
    return {
      message: 'Generating ZK proof...',
      detail: longPhaseDetails[index],
    };
  }

  return {
    message: 'Almost there - finalizing proof...',
    detail: 'Completing final proof checks.',
  };
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function truncateHash(hash) {
  if (!hash) return '-';
  return `${hash.slice(0, 12)}...${hash.slice(-8)}`;
}

async function computeProofHash(proof, publicSignals) {
  const encoded = new TextEncoder().encode(JSON.stringify({ proof, publicSignals }));
  if (globalThis.crypto?.subtle?.digest) {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // Fallback for insecure contexts (e.g., LAN HTTP on mobile/other devices).
  // Not cryptographically strong, but stable enough for UI display/copy.
  let hash = 2166136261;
  for (let i = 0; i < encoded.length; i += 1) {
    hash ^= encoded[i];
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function setProgress(percent, isSpinning) {
  const p = Math.max(0, Math.min(100, Math.round(percent)));
  const circumference = 2 * Math.PI * 68;
  progressPercentEl.textContent = `${timelineElapsedSeconds}s`;
  elapsedTimeEl.textContent = `~${Math.round(expectedDurationMs / 1000)}s est.`;
  progressRingBarEl.style.strokeDashoffset = String(circumference * (1 - p / 100));
  progressRingWrapEl.classList.toggle('is-spinning', Boolean(isSpinning));
}

function setProvingStep(message, detail, percent, isSpinning) {
  provingMessageEl.textContent = message;
  provingDetailEl.textContent = detail;
  setProgress(percent, isSpinning);
}

function startElapsedTimer() {
  elapsedStartedAt = Date.now();
  clearInterval(elapsedTimerId);
  elapsedTimerId = window.setInterval(() => {
    elapsedTimeEl.textContent = `${Math.floor((Date.now() - elapsedStartedAt) / 1000)}s`;
  }, 250);
}

function stopElapsedTimer() {
  clearInterval(elapsedTimerId);
  return Date.now() - elapsedStartedAt;
}

function startProgressTimeline() {
  clearInterval(timelineTimerId);
  timelineElapsedSeconds = 0;
  timelineProgressValue = 0;
  setProgress(0, true);

  timelineTimerId = window.setInterval(() => {
    const elapsedMs = Date.now() - elapsedStartedAt;
    timelineElapsedSeconds = Math.max(0, Math.floor(elapsedMs / 1000));
    const raw = PRE_COMPLETE_MAX * (1 - Math.exp(-(2.4 * elapsedMs) / expectedDurationMs));
    timelineProgressValue = Math.min(PRE_COMPLETE_MAX, raw);
    const status = getTimelineStatus(timelineElapsedSeconds);
    setProvingStep(status.message, status.detail, timelineProgressValue, true);
  }, 200);
}

function stopProgressTimeline() {
  clearInterval(timelineTimerId);
}

function animateProgressToComplete() {
  return new Promise((resolve) => {
    const start = performance.now();
    const from = timelineProgressValue;
    const durationMs = 500;

    function step(now) {
      const t = Math.min(1, (now - start) / durationMs);
      const eased = 1 - (1 - t) * (1 - t);
      const value = from + (100 - from) * eased;
      setProgress(value, false);
      if (t < 1) {
        requestAnimationFrame(step);
      } else {
        resolve();
      }
    }

    requestAnimationFrame(step);
  });
}

function handleFriendlyError(error) {
  const message = String(error?.message || '').toLowerCase();
  if (message.includes('too many values for input signal') || message.includes('not all inputs have been set')) {
    return 'Local proving artifacts are stale after a circuit update. Refresh the page (or clear site data) and try again.';
  }
  if (message.includes('name hash mismatch') || message.includes('line: 71')) {
    return 'Expected name does not exactly match the Aadhaar name in the signed QR. Use exact casing and spacing.';
  }
  if (message.includes('memory') || message.includes('allocation') || message.includes('out of bounds')) {
    return 'Proof generation failed - your device may not have enough memory. Try on a desktop browser.';
  }
  if (message.includes('numeric') || message.includes('qr')) {
    return 'Please provide valid Aadhaar QR data before generating the proof.';
  }
  return 'Proof generation failed. Please try again.';
}

function getArtifactPaths() {
  return {
    wasmPath: `${WASM_PATH}${artifactVersionToken}`,
    zkeyPath: `${ZKEY_PATH}${artifactVersionToken}`,
  };
}

function int64ToBytes(num) {
  const arr = new ArrayBuffer(8);
  const view = new DataView(arr);
  view.setInt32(4, num, false);
  return new Uint8Array(arr);
}

function uint8ArrayToStringArray(bytes) {
  return Array.from(bytes).map((x) => x.toString());
}

function convertBigIntToByteArray(bigIntValue) {
  const byteLength = Math.max(1, Math.ceil(bigIntValue.toString(2).length / 8));
  const result = new Uint8Array(byteLength);
  let current = bigIntValue;
  let index = 0;
  while (current > 0n) {
    result[index] = Number(current % 256n);
    current /= 256n;
    index += 1;
  }
  return result.reverse();
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (let i = 0; i < bytes.length; i += 1) {
    value = (value << 8n) + BigInt(bytes[i]);
  }
  return value;
}

function splitToWords(number, wordSize, numberElements) {
  let t = number;
  const words = [];
  for (let i = 0n; i < numberElements; i += 1n) {
    words.push((t % (2n ** wordSize)).toString());
    t /= 2n ** wordSize;
  }
  if (t !== 0n) {
    throw new Error('Number does not fit in expected word size.');
  }
  return words;
}

function sha256Pad(message, maxShaBytes) {
  const msgLen = message.length * 8;
  const msgLenBytes = int64ToBytes(msgLen);
  const withStopBit = new Uint8Array(message.length + 1);
  withStopBit.set(message, 0);
  withStopBit[message.length] = 0x80;

  let padded = withStopBit;
  while (((padded.length + msgLenBytes.length) * 8) % 512 !== 0) {
    const tmp = new Uint8Array(padded.length + 1);
    tmp.set(padded, 0);
    padded = tmp;
  }

  const withLength = new Uint8Array(padded.length + msgLenBytes.length);
  withLength.set(padded, 0);
  withLength.set(msgLenBytes, padded.length);

  if (withLength.length > maxShaBytes) {
    throw new Error(`Padded message (${withLength.length}) exceeds max (${maxShaBytes}).`);
  }

  const maxPadded = new Uint8Array(maxShaBytes);
  maxPadded.set(withLength, 0);
  return [maxPadded, withLength.length];
}

function findDelimiterIndices(paddedBytes) {
  const delimiterIndices = [];
  for (let i = 0; i < paddedBytes.length; i += 1) {
    if (paddedBytes[i] === 255) {
      delimiterIndices.push(i.toString());
      if (delimiterIndices.length === 18) break;
    }
  }
  if (delimiterIndices.length < 18) {
    throw new Error('Could not find all 18 field delimiters in QR data.');
  }
  return delimiterIndices;
}

function extractQrPhotoBytes(signedDataBytes) {
  const delimiterIndices = [];
  for (let i = 0; i < signedDataBytes.length; i += 1) {
    if (signedDataBytes[i] === 255) {
      delimiterIndices.push(i);
      if (delimiterIndices.length === 18) break;
    }
  }

  if (delimiterIndices.length < 18) {
    throw new Error('Could not locate photo delimiter in signed QR payload.');
  }

  const photoStart = delimiterIndices[17] + 1;
  return Array.from(signedDataBytes.slice(photoStart));
}

async function hashExpectedName(expectedName) {
  const response = await fetch('/api/verify/hash-name', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: expectedName }),
  });

  if (!response.ok) {
    throw new Error(`Name hash API error (${response.status}): ${await response.text()}`);
  }

  const body = await response.json();
  if (!body?.nameHash) {
    throw new Error('Name hash API returned an invalid response');
  }

  return body.nameHash;
}

function prepareCircuitInputs(qrNumericString, pubKeyWords, minAge, nameHash, maxDataLength, onPhase) {
  onPhase('Decompressing Aadhaar QR data...');
  const qrBigInt = BigInt(qrNumericString);
  const compressedQrBytes = convertBigIntToByteArray(qrBigInt);
  const decompressedBytes = window.pako.inflate(compressedQrBytes);

  if (decompressedBytes.length <= 256) {
    throw new Error('QR data is too short after decompression.');
  }

  onPhase('Extracting signed payload...');
  const signature = decompressedBytes.slice(decompressedBytes.length - 256);
  const signedData = decompressedBytes.slice(0, decompressedBytes.length - 256);
  const [paddedMessage, messageLength] = sha256Pad(signedData, maxDataLength);
  const delimiterIndices = findDelimiterIndices(paddedMessage);
  const signatureBigInt = bytesToBigInt(signature);
  const qrPhotoBytes = extractQrPhotoBytes(signedData);

  onPhase('Computing witness for ZK circuit...');
  return {
    circuitInputs: {
      qrDataPadded: uint8ArrayToStringArray(paddedMessage),
      qrDataPaddedLength: messageLength.toString(),
      delimiterIndices,
      signature: splitToWords(signatureBigInt, 121n, 17n),
      pubKey: pubKeyWords,
      minAge: String(minAge),
      signalHash: '0',
      nameHash,
    },
    qrPhotoBytes,
  };
}

async function getProofKeyWords() {
  if (!proofKeyPromise) {
    proofKeyPromise = fetch('/api/proof/key')
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`Proof key API error (${response.status}): ${await response.text()}`);
        }
        return response.json();
      })
      .then((result) => {
        if (!Array.isArray(result.pubKeyWords) || result.pubKeyWords.length !== 17) {
          throw new Error('Invalid pubKeyWords response from /api/proof/key');
        }
        return result.pubKeyWords;
      });
  }
  return proofKeyPromise;
}

async function getProofInfo() {
  if (!proofInfoPromise) {
    proofInfoPromise = fetch('/api/proof/info')
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`Proof info API error (${response.status}): ${await response.text()}`);
        }
        return response.json();
      })
      .then((result) => {
        const maxDataLength = Number(result?.parameters?.maxDataLength);
        if (!Number.isInteger(maxDataLength) || maxDataLength < 512) {
          throw new Error('Invalid maxDataLength in /api/proof/info response');
        }

        artifactVersionToken = result?.artifactVersion
          ? `?v=${encodeURIComponent(result.artifactVersion)}`
          : '';
        return result;
      });
  }
  return proofInfoPromise;
}

async function warmupArtifacts() {
  if (LOCAL_ARTIFACT_MODE !== 'buffer') {
    return;
  }

  if (!artifactWarmupPromise) {
    const { wasmPath, zkeyPath } = getArtifactPaths();
    artifactWarmupPromise = callProverWorker('warmup', {
      wasmPath,
      zkeyPath,
      artifactStrategy: LOCAL_ARTIFACT_MODE,
      cachePolicy: LOCAL_ARTIFACT_CACHE_POLICY,
    }).then((payload) => {
      logBench('prove-worker-warmup', {
        cacheHit: Boolean(payload?.cacheHit),
        warmupMs: Number(payload?.warmupMs) || null,
        artifactBytes: Number(payload?.bytes) || null,
        proveMode: payload?.proveMode || LOCAL_ARTIFACT_MODE,
      });
    });
  }
  return artifactWarmupPromise;
}

function ensureProverWorker() {
  if (proverWorker) return proverWorker;
  proverWorker = new Worker(PROVER_WORKER_PATH);
  proverWorker.onerror = (error) => {
    console.error('Prover worker crashed:', error.message);
    proverWorker?.terminate();
    proverWorker = undefined;
  };
  return proverWorker;
}

function callProverWorker(type, payload, onPhase) {
  const worker = ensureProverWorker();
  const requestId = ++workerRequestId;

  return new Promise((resolve, reject) => {
    const onMessage = (event) => {
      const { type: messageType, payload: messagePayload } = event.data || {};
      if (messagePayload?.requestId !== requestId) return;

      if (messageType === 'phase' && messagePayload?.message) {
        onPhase?.(messagePayload.message, messagePayload.spinning);
        return;
      }

      if (messageType === 'ready' || messageType === 'result') {
        worker.removeEventListener('message', onMessage);
        resolve(messagePayload);
        return;
      }

      if (messageType === 'error') {
        worker.removeEventListener('message', onMessage);
        reject(new Error(messagePayload?.message || 'Worker proof generation failed'));
      }
    };

    worker.addEventListener('message', onMessage);
    worker.postMessage({ type, payload: { ...payload, requestId } });
  });
}

function runProofInWorker(circuitInputs, onPhase) {
  const { wasmPath, zkeyPath } = getArtifactPaths();
  if (!window.Worker) {
    if (!window.snarkjs) throw new Error('Web Workers unavailable and fallback prover is not loaded.');
    return window.snarkjs.groth16.fullProve(circuitInputs, wasmPath, zkeyPath);
  }

  return callProverWorker(
    'prove',
    {
      circuitInputs,
      wasmPath,
      zkeyPath,
      artifactStrategy: LOCAL_ARTIFACT_MODE,
      cachePolicy: LOCAL_ARTIFACT_CACHE_POLICY,
    },
    onPhase
  );
}

async function verifyProof(proof, publicSignals, qrPhotoBytes) {
  const response = await fetch('/api/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proof, publicSignals, qrPhotoBytes }),
  });
  if (!response.ok) {
    throw new Error(`Verify API error (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

async function generateProofOnServer(circuitInputs) {
  const response = await fetch('/api/proof/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ circuitInputs }),
  });

  if (!response.ok) {
    throw new Error(`Server proof API error (${response.status}): ${await response.text()}`);
  }

  return response.json();
}

async function onGenerateClick() {
  let proofMs = 0;
  try {
    generateBtnEl.disabled = true;

    if (!window.pako) throw new Error('pako failed to load in browser. Refresh and try again.');
    if (!window.Worker) throw new Error('This browser does not support Web Workers required for safe proving.');

    clearQrValidation();
    const qrData = qrInputEl.value.trim();
    if (!qrData) {
      setQrValidation('Please scan or paste QR data');
      return;
    }
    if (!/^\d+$/.test(qrData)) {
      setQrValidation('QR data must contain only numbers');
      return;
    }

    const minAge = Number(minAgeInputEl.value);
    if (!Number.isInteger(minAge) || minAge < 1 || minAge > 120) {
      throw new Error('Minimum age must be an integer between 1 and 120.');
    }

    const expectedName = expectedNameInputEl?.value || '';
    if (!expectedName.trim()) {
      throw new Error('Please enter the expected name for identity binding.');
    }

    activeProvingMode = getSelectedProvingMode();

    setCardState('proving');
    setProvingStep('Loading proving key...', 'Initializing proving artifacts in this browser.', 0, true);
    startElapsedTimer();
    startProgressTimeline();

    const t0 = performance.now();
    const [pubKeyWords, proofInfo] = await Promise.all([getProofKeyWords(), getProofInfo()]);
    expectedDurationMs = pickExpectedDurationMs(proofInfo);
    logBench('prove-eta-selected', {
      expectedDurationMs,
      fromHistory: loadProofHistory().length > 0,
      profileHintMs: Number(proofInfo?.performanceHints?.expectedProofMs) || null,
    });

    const inputPrepStart = performance.now();
    const nameHash = await hashExpectedName(expectedName);
    const prepared = prepareCircuitInputs(
      qrData,
      pubKeyWords,
      minAge,
      nameHash,
      Number(proofInfo.parameters.maxDataLength),
      () => {}
    );
    const { circuitInputs, qrPhotoBytes } = prepared;
    const inputPrepMs = Math.round(performance.now() - inputPrepStart);
    logBench('prove-input-ready', { inputPrepMs });

    let proofResult;
    let workerProveMs = 0;
    const proofStart = performance.now();

    if (activeProvingMode === 'server') {
      setProvingStep('Sending proving request to server...', 'Server-side mode selected for proof generation.', timelineProgressValue, true);
      proofResult = await generateProofOnServer(circuitInputs);
      workerProveMs = Math.round(performance.now() - proofStart);
      proofMs = Number(proofResult?.metadata?.generationTime) || workerProveMs;
      logBench('prove-server-done', { serverRoundTripMs: workerProveMs, serverProofMs: proofMs });
    } else {
      proofResult = await runProofInWorker(circuitInputs, (message, spinning) => {
        if (message.toLowerCase().includes('generating')) {
          setProvingStep('Generating ZK proof...', 'This is the computationally intensive step.', timelineProgressValue, Boolean(spinning));
        }
      });
      workerProveMs = Math.round(performance.now() - proofStart);
      const workerPerf = proofResult?.perf || {};
      proofMs = Number(workerPerf.fullProveMs) || workerProveMs;
      logBench('prove-worker-done', {
        workerRoundTripMs: workerProveMs,
        workerProveMs: Number(workerPerf.fullProveMs) || null,
        workerWarmupMs: Number(workerPerf.warmupMs) || null,
        workerCacheHit: Boolean(workerPerf.cacheHit),
        workerArtifactBytes: Number(workerPerf.artifactBytes) || null,
        workerProveMode: workerPerf.proveMode || LOCAL_ARTIFACT_MODE,
      });
    }

    const { proof, publicSignals } = proofResult;

    setProvingStep('Finalizing proof...', 'Validating proof with the verifier endpoint.', timelineProgressValue, true);
    const verifyStart = performance.now();
    const verifyResponse = await verifyProof(proof, publicSignals, qrPhotoBytes);
    const verifyMs = performance.now() - verifyStart;

    stopProgressTimeline();
    await animateProgressToComplete();
    stopElapsedTimer();

    const isVerified = Boolean(verifyResponse?.valid && verifyResponse?.eligible);
    if (!isVerified) {
      if (verifyResponse?.claims?.timestampFreshnessReason === 'stale') {
        throw new Error('This Aadhaar QR is too old for the current verifier freshness policy.');
      }
      if (verifyResponse?.claims?.timestampFreshnessReason === 'timestamp_in_future') {
        throw new Error('Aadhaar QR timestamp appears invalid (future timestamp).');
      }
      throw new Error('Verifier rejected this proof.');
    }

    recordProofDuration(proofMs);

    const proofJson = JSON.stringify(proof);
    proofHashFull = await computeProofHash(proof, publicSignals);

    const minAgeClaim = Number(verifyResponse?.claims?.minAgeUsed);
    const effectiveMinAge = Number.isFinite(minAgeClaim) ? minAgeClaim : minAge;
    resultHeadlineEl.textContent = `Age >= ${effectiveMinAge}: Verified | Identity: Bound`;
    revealedAgeRowEl.textContent = `Age >= ${effectiveMinAge}: Yes`;
    proofTimeValueEl.textContent = formatMs(proofMs);
    proofSizeValueEl.textContent = formatBytes(new TextEncoder().encode(proofJson).length);
    verifyTimeValueEl.textContent = formatMs(verifyMs);
    proofHashValueEl.textContent = truncateHash(proofHashFull);

    logBench('prove-complete', {
      proofGenerationMs: proofMs,
      inputPrepMs,
      workerProveMs,
      verifyRequestMs: Math.round(verifyMs),
      totalMs: Math.round(performance.now() - t0),
    });
    setCardState('result');
  } catch (error) {
    stopProgressTimeline();
    stopElapsedTimer();
    errorMessageEl.textContent = handleFriendlyError(error);
    setCardState('error');
  } finally {
    await stopScanner();
    generateBtnEl.disabled = false;
  }
}

async function startScanner() {
  const previousQrInput = qrInputEl.value.trim();

  // Reset stale input so a failed scan cannot silently fall back to previously prefilled/demo data.
  qrInputEl.value = '';

  const decodeQrFromCanvas = async (canvas, ctx) => {
    if (typeof window.BarcodeDetector !== 'undefined') {
      try {
        const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        const barcodes = await detector.detect(canvas);
        const raw = barcodes?.[0]?.rawValue;
        if (raw) return raw;
      } catch (error) {
        // Ignore and fall back to jsQR.
      }
    }

    if (typeof window.jsQR === 'function') {
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const options = [{ inversionAttempts: 'dontInvert' }, { inversionAttempts: 'attemptBoth' }];
      for (const option of options) {
        const result = window.jsQR(imageData.data, canvas.width, canvas.height, option);
        if (result?.data) return result.data;
      }
    }

    return null;
  };

  const decodeQrFromImageFile = async (file) => {
    if (!file) return null;

    const objectUrl = URL.createObjectURL(file);
    try {
      const image = await new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => reject(new Error('Failed to read selected image.'));
        img.src = objectUrl;
      });

      const imageWidth = image.naturalWidth || image.width;
      const imageHeight = image.naturalHeight || image.height;
      if (!imageWidth || !imageHeight) return null;

      const attemptScales = [1, 0.75, 0.5, 0.35];
      const maxDecodeSide = 1800;

      for (const scale of attemptScales) {
        const baseWidth = Math.max(240, Math.round(imageWidth * scale));
        const baseHeight = Math.max(240, Math.round(imageHeight * scale));
        const capRatio = Math.min(1, maxDecodeSide / Math.max(baseWidth, baseHeight));
        const width = Math.max(240, Math.round(baseWidth * capRatio));
        const height = Math.max(240, Math.round(baseHeight * capRatio));

        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        if (!ctx) continue;

        ctx.drawImage(image, 0, 0, width, height);

        const direct = await decodeQrFromCanvas(canvas, ctx);
        if (direct) return direct;

        // Retry on rotated copies for mobile camera orientation mismatches.
        const rotateAngles = [90, 180, 270];
        for (const angle of rotateAngles) {
          const rotated = document.createElement('canvas');
          const rotatedCtx = rotated.getContext('2d', { willReadFrequently: true });
          if (!rotatedCtx) continue;

          if (angle % 180 === 0) {
            rotated.width = width;
            rotated.height = height;
          } else {
            rotated.width = height;
            rotated.height = width;
          }

          rotatedCtx.translate(rotated.width / 2, rotated.height / 2);
          rotatedCtx.rotate((angle * Math.PI) / 180);
          rotatedCtx.drawImage(canvas, -width / 2, -height / 2);

          const rotatedResult = await decodeQrFromCanvas(rotated, rotatedCtx);
          if (rotatedResult) return rotatedResult;
        }
      }

      return null;
    } finally {
      URL.revokeObjectURL(objectUrl);
    }
  };

  const captureAndDecodeQrImage = async () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    // Do not force camera-only capture so mobile users can pick existing gallery images.
    input.style.display = 'none';
    document.body.appendChild(input);

    try {
      const file = await new Promise((resolve) => {
        input.onchange = () => resolve(input.files?.[0] || null);
        input.oncancel = () => resolve(null);
        input.click();
      });

      if (!file) return null;
      return decodeQrFromImageFile(file);
    } finally {
      input.remove();
    }
  };

  // On mobile insecure contexts, live camera APIs are blocked; use capture fallback.
  if (MOBILE_USER_AGENT && !window.isSecureContext) {
    inputHintEl.textContent = 'Live camera requires HTTPS on mobile. Opening camera capture fallback...';
    try {
      const qrText = await captureAndDecodeQrImage();
      if (qrText) {
        qrInputEl.value = qrText.trim();
        setPastePanelVisible(true);
        showToast('QR data captured.');
        return;
      }
    } catch (error) {
      // Fall through to manual paste guidance below.
    }
    inputHintEl.textContent = 'Could not decode QR from captured image. You can paste QR data manually.';
    if (previousQrInput) qrInputEl.value = previousQrInput;
    setQrValidation('Could not detect a QR code in that photo. Try a clearer photo or paste QR data.');
    setPastePanelVisible(true);
    return;
  }

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    inputHintEl.textContent = 'Camera scanning is unavailable in this browser. Opening image capture fallback...';
    try {
      const qrText = await captureAndDecodeQrImage();
      if (qrText) {
        qrInputEl.value = qrText.trim();
        setPastePanelVisible(true);
        showToast('QR data captured.');
        return;
      }
    } catch (error) {
      // Fall through to paste mode.
    }
    if (previousQrInput) qrInputEl.value = previousQrInput;
    setQrValidation('Could not detect a QR code in that photo. Try a clearer photo or paste QR data.');
    setPastePanelVisible(true);
    return;
  }

  if (scannerStream) {
    return;
  }

  scannerPanelEl.hidden = false;
  try {
    const preferredConstraints = {
      audio: false,
      video: {
        facingMode: { ideal: 'environment' },
      },
    };

    scannerStream = await navigator.mediaDevices.getUserMedia(preferredConstraints);

    scannerPanelEl.hidden = false;
    const viewportEl = document.getElementById('scannerViewport');
    viewportEl.innerHTML = '';

    scannerVideoEl = document.createElement('video');
    scannerVideoEl.setAttribute('playsinline', 'true');
    scannerVideoEl.autoplay = true;
    scannerVideoEl.muted = true;
    scannerVideoEl.srcObject = scannerStream;
    scannerVideoEl.style.width = '100%';
    scannerVideoEl.style.height = '100%';
    viewportEl.appendChild(scannerVideoEl);

    scannerCanvasEl = document.createElement('canvas');
    scannerCanvasCtx = scannerCanvasEl.getContext('2d', { willReadFrequently: true });

    await scannerVideoEl.play();
    inputHintEl.textContent = 'Camera active. Point it at the Aadhaar QR code.';

    const useBarcodeDetector = typeof window.BarcodeDetector !== 'undefined';
    const detector = useBarcodeDetector ? new window.BarcodeDetector({ formats: ['qr_code'] }) : null;

    const scanLoop = async () => {
      if (!scannerVideoEl || !scannerStream) return;
      if (scannerVideoEl.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
        const width = scannerVideoEl.videoWidth || 640;
        const height = scannerVideoEl.videoHeight || 480;
        scannerCanvasEl.width = width;
        scannerCanvasEl.height = height;
        scannerCanvasCtx.drawImage(scannerVideoEl, 0, 0, width, height);

        let qrText = null;

        if (detector) {
          const barcodes = await detector.detect(scannerCanvasEl);
          qrText = barcodes?.[0]?.rawValue || null;
        } else if (typeof window.jsQR === 'function') {
          const imageData = scannerCanvasCtx.getImageData(0, 0, width, height);
          const result = window.jsQR(imageData.data, width, height, { inversionAttempts: 'dontInvert' });
          qrText = result?.data || null;
        }

        if (qrText) {
          qrInputEl.value = qrText.trim();
          setPastePanelVisible(true);
          showToast('QR data captured.');
          await stopScanner();
          return;
        }
      }

      scannerFrameRequest = requestAnimationFrame(() => {
        scanLoop().catch(() => {
          // Keep scanning on transient frame decode errors.
          scannerFrameRequest = requestAnimationFrame(() => scanLoop().catch(() => {}));
        });
      });
    };

    scannerFrameRequest = requestAnimationFrame(() => scanLoop().catch(() => {}));
  } catch (error) {
    await stopScanner();
    scannerPanelEl.hidden = true;
    const errorText = `${error?.name || ''} ${error?.message || ''}`.toLowerCase();
    const isPermissionIssue = errorText.includes('permission') || errorText.includes('notallowederror');
    const isSecureContextIssue = errorText.includes('secure context') || !window.isSecureContext;
    if (MOBILE_USER_AGENT) {
      try {
        const qrText = await captureAndDecodeQrImage();
        if (qrText) {
          qrInputEl.value = qrText.trim();
          setPastePanelVisible(true);
          showToast('QR data captured.');
          return;
        }
      } catch (captureError) {
        // Fall back to paste mode with a precise message.
      }
    }

    inputHintEl.textContent = isPermissionIssue
      ? 'Camera permission denied. Allow camera access in browser settings and try again.'
      : isSecureContextIssue
        ? 'Mobile camera requires HTTPS (or localhost). Open this app over HTTPS to scan live.'
        : 'Unable to start camera scanning. You can paste QR data manually.';
    if (previousQrInput) qrInputEl.value = previousQrInput;
    setQrValidation('Scan failed. Try another photo/angle, or paste QR data manually.');
    setPastePanelVisible(true);
  }
}

async function stopScanner() {
  if (scannerFrameRequest) {
    cancelAnimationFrame(scannerFrameRequest);
    scannerFrameRequest = undefined;
  }

  if (scannerStream) {
    for (const track of scannerStream.getTracks()) {
      track.stop();
    }
    scannerStream = undefined;
  }

  if (scannerVideoEl) {
    scannerVideoEl.pause();
    scannerVideoEl.srcObject = null;
    scannerVideoEl.remove();
    scannerVideoEl = undefined;
  }

  scannerCanvasEl = undefined;
  scannerCanvasCtx = undefined;
  html5QrCode = undefined;
  scannerPanelEl.hidden = true;

  const viewportEl = document.getElementById('scannerViewport');
  if (viewportEl) {
    viewportEl.innerHTML = '';
  }
}

function resetFlow() {
  stopProgressTimeline();
  clearQrValidation();
  setCardState('input');
  setProgress(0, false);
  timelineElapsedSeconds = 0;
  elapsedTimeEl.textContent = `~${Math.round(expectedDurationMs / 1000)}s est.`;
  provingMessageEl.textContent = 'Preparing secure proof generation...';
  provingDetailEl.textContent = 'This usually takes around one minute on desktop browsers.';
}

copyHashBtnEl.addEventListener('click', async () => {
  if (!proofHashFull) return;
  try {
    await navigator.clipboard.writeText(proofHashFull);
    showToast('Proof copied!');
  } catch (error) {
    showToast('Copy failed');
  }
});

togglePasteBtnEl.addEventListener('click', () => setPastePanelVisible(pastePanelEl.hidden));
qrInputEl.addEventListener('input', () => {
  if (qrInputEl.classList.contains('input-invalid')) {
    clearQrValidation();
  }
});

agePillsEl.addEventListener('click', (event) => {
  const target = event.target.closest('.age-pill');
  if (!target) return;
  if (target.dataset.age === 'custom') {
    setAge(Number(minAgeInputEl.value || 18), true);
  } else {
    setAge(Number(target.dataset.age), false);
  }
});

minAgeInputEl.addEventListener('change', () => {
  const value = Number(minAgeInputEl.value);
  if (Number.isInteger(value) && value >= 1 && value <= 120) {
    setAge(value, !customAgePanelEl.hidden);
  }
});

customAgeToggleEl.addEventListener('click', () => setAge(Number(minAgeInputEl.value || 18), true));
provingModeEl?.addEventListener('change', updateModeHint);
scanQrBtnEl.addEventListener('click', () => startScanner().catch(() => {}));
stopScanBtnEl.addEventListener('click', () => stopScanner().catch(() => {}));
verifyAgainBtnEl.addEventListener('click', resetFlow);
tryAgainBtnEl.addEventListener('click', resetFlow);
generateBtnEl.addEventListener('click', onGenerateClick);

setAge(18, false);
setPastePanelVisible(false);
setCardState('input');
setProgress(0, false);

if (provingModeEl && (!BROWSER_ISOLATED || LOW_MEMORY_MODE || AVAILABLE_CORES <= 2)) {
  provingModeEl.value = 'server';
}

if (DEMO_PREFILL_ENABLED && !qrInputEl.value.trim()) {
  qrInputEl.value = PREFILLED_QR_DATA;
}

if (LOW_MEMORY_MODE) {
  inputHintEl.textContent = 'Low-memory mode enabled. Consider server-side proving for faster results.';
} else {
  warmupArtifacts().catch((error) => {
    console.warn('Artifact warmup skipped:', error.message);
  });
}

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

updateModeHint();

logBench('browser-capabilities', {
  crossOriginIsolated: BROWSER_ISOLATED,
  hardwareConcurrency: AVAILABLE_CORES,
  lowMemoryMode: LOW_MEMORY_MODE,
  localArtifactMode: LOCAL_ARTIFACT_MODE,
  localArtifactCachePolicy: LOCAL_ARTIFACT_CACHE_POLICY,
  defaultMode: getSelectedProvingMode(),
});

