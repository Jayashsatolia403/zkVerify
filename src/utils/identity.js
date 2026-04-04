import { buildPoseidon } from 'circomlibjs';

const FIELD_CHUNK_BYTES = 31;
const NAME_BYTES = 64;
const PHOTO_PREFIX_BYTES = 256;

let poseidonPromise;

async function getPoseidon() {
  if (!poseidonPromise) {
    poseidonPromise = buildPoseidon();
  }
  return poseidonPromise;
}

function packBytes(inputBytes, totalLength) {
  const bytes = inputBytes instanceof Uint8Array ? inputBytes : Uint8Array.from(inputBytes || []);
  const fixed = new Uint8Array(totalLength);
  fixed.set(bytes.slice(0, totalLength));

  const out = [];
  const fieldCount = Math.ceil(totalLength / FIELD_CHUNK_BYTES);
  for (let chunk = 0; chunk < fieldCount; chunk += 1) {
    const base = chunk * FIELD_CHUNK_BYTES;
    let value = 0n;
    for (let i = 0; i < FIELD_CHUNK_BYTES; i += 1) {
      const idx = base + i;
      if (idx >= fixed.length) break;
      value += BigInt(fixed[idx]) << (BigInt(i) * 8n);
    }
    out.push(value);
  }

  return out;
}

async function poseidonHashPacked(packed) {
  const poseidon = await getPoseidon();
  const hash = poseidon(packed);
  return poseidon.F.toString(hash);
}

export async function hashName(name) {
  const bytes = new TextEncoder().encode(name || '');
  if (bytes.length > NAME_BYTES) {
    throw new Error(`name is too long: ${bytes.length} bytes (max ${NAME_BYTES})`);
  }
  return poseidonHashPacked(packBytes(bytes, NAME_BYTES));
}

export async function hashPhotoPrefix(photoBytes) {
  return poseidonHashPacked(packBytes(photoBytes, PHOTO_PREFIX_BYTES));
}

export async function verifyPhotoHash(photoBytes, expectedHash) {
  const computedHash = await hashPhotoPrefix(photoBytes);
  return computedHash === String(expectedHash);
}

