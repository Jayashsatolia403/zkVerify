import { groth16, Groth16Proof, PublicSignals } from 'snarkjs'
import { buildPoseidon } from 'circomlibjs'

const FIELD_CHUNK_BYTES = 31
const NAME_BYTES = 64
const PHOTO_PREFIX_BYTES = 256

let poseidonPromise: Promise<any> | undefined

async function getPoseidon() {
  if (!poseidonPromise) {
    poseidonPromise = buildPoseidon()
  }
  return poseidonPromise
}

function packBytes(bytes: Uint8Array, totalLength: number): bigint[] {
  const fixed = new Uint8Array(totalLength)
  fixed.set(bytes.slice(0, totalLength))

  const fieldCount = Math.ceil(totalLength / FIELD_CHUNK_BYTES)
  const packed: bigint[] = []

  for (let chunkIndex = 0; chunkIndex < fieldCount; chunkIndex += 1) {
    let value = 0n
    const base = chunkIndex * FIELD_CHUNK_BYTES
    for (let byteIndex = 0; byteIndex < FIELD_CHUNK_BYTES; byteIndex += 1) {
      const idx = base + byteIndex
      if (idx >= fixed.length) break
      value += BigInt(fixed[idx]) << (BigInt(byteIndex) * 8n)
    }
    packed.push(value)
  }

  return packed
}

async function poseidonHashPacked(packed: bigint[]): Promise<string> {
  const poseidon = await getPoseidon()
  const hash = poseidon(packed)
  return poseidon.F.toString(hash)
}

export async function hashName(name: string): Promise<string> {
  const bytes = new TextEncoder().encode(name)
  if (bytes.length > NAME_BYTES) {
    throw new Error(`name is too long: ${bytes.length} bytes (max ${NAME_BYTES})`)
  }

  const packed = packBytes(bytes, NAME_BYTES)
  return poseidonHashPacked(packed)
}

export async function hashPhotoPrefix(photoBytes: Uint8Array | number[]): Promise<string> {
  const bytes = photoBytes instanceof Uint8Array ? photoBytes : Uint8Array.from(photoBytes)
  const packed = packBytes(bytes, PHOTO_PREFIX_BYTES)
  return poseidonHashPacked(packed)
}

export async function verifyPhotoHash(
  photoBytes: Uint8Array | number[],
  expectedHash: string | bigint
): Promise<boolean> {
  const computed = await hashPhotoPrefix(photoBytes)
  return computed === expectedHash.toString()
}

export async function verifyProof(
  verificationKey: unknown,
  proof: Groth16Proof,
  publicSignals: PublicSignals
): Promise<boolean> {
  return groth16.verify(verificationKey as any, publicSignals, proof)
}

