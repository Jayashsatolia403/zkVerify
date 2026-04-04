import {
  convertBigIntToByteArray,
  decompressByteArray,
  splitToWords,
} from './utils'
import { AnonAadhaarArgs } from './types'
import {
  bufferToHex,
  Uint8ArrayToCharArray,
} from '@zk-email/helpers/dist/binary-format'
import { sha256Pad } from '@zk-email/helpers/dist/sha-utils'
import { Buffer } from 'buffer'
import { pki } from 'node-forge'
import { ArgumentTypeName } from '@pcd/pcd-types'
import { hash } from './hash'
import { hashName } from './identity'

interface GenerateArgsOptions {
  qrData: string
  certificateFile: string
  minAge?: number
  signal?: string
  expectedName?: string
  nameHash?: string
}

/**
 * Extract all the information needed to generate the witness from the QRCode data.
 * @param qrData QrCode Data
 * @returns {witness}
 */
export const generateArgs = async ({
  qrData,
  certificateFile,
  minAge = 18,
  signal,
  expectedName,
  nameHash,
}: GenerateArgsOptions): Promise<AnonAadhaarArgs> => {
  const bigIntData = BigInt(qrData)

  const byteArray = convertBigIntToByteArray(bigIntData)

  const decompressedByteArray = decompressByteArray(byteArray)

  // Read signature data
  const signature = decompressedByteArray.slice(
    decompressedByteArray.length - 256,
    decompressedByteArray.length
  )

  const signedData = decompressedByteArray.slice(
    0,
    decompressedByteArray.length - 256
  )

  const RSAPublicKey = pki.certificateFromPem(certificateFile).publicKey
  const publicKey = (RSAPublicKey as pki.rsa.PublicKey).n.toString(16)

  const pubKeyBigInt = BigInt('0x' + publicKey)

  const signatureBigint = BigInt(
    '0x' + bufferToHex(Buffer.from(signature)).toString()
  )

  const [paddedMessage, messageLength] = sha256Pad(signedData, 512 * 3)

  const delimiterIndices: number[] = []
  for (let i = 0; i < paddedMessage.length; i++) {
    if (paddedMessage[i] === 255) {
      delimiterIndices.push(i)
    }
    if (delimiterIndices.length === 18) {
      break
    }
  }

  if (!Number.isInteger(minAge) || minAge < 0 || minAge > 255) {
    throw new Error('minAge must be an integer between 0 and 255')
  }

  // Set signal to 1 by default if no signal is set
  const signalHash = signal ? hash(signal) : hash(1)
  const computedNameHash =
    nameHash ||
    (typeof expectedName === 'string' ? await hashName(expectedName) : undefined)

  if (!computedNameHash) {
    throw new Error('nameHash or expectedName is required for identity-bound proofs')
  }

  const anonAadhaarArgs: AnonAadhaarArgs = {
    qrDataPadded: {
      argumentType: ArgumentTypeName.StringArray,
      value: Uint8ArrayToCharArray(paddedMessage),
    },
    qrDataPaddedLength: {
      argumentType: ArgumentTypeName.Number,
      value: messageLength.toString(),
    },
    delimiterIndices: {
      argumentType: ArgumentTypeName.StringArray,
      value: delimiterIndices.map(elem => elem.toString()),
    },
    signature: {
      argumentType: ArgumentTypeName.StringArray,
      value: splitToWords(signatureBigint, BigInt(121), BigInt(17)),
    },
    pubKey: {
      argumentType: ArgumentTypeName.StringArray,
      value: splitToWords(pubKeyBigInt, BigInt(121), BigInt(17)),
    },
    minAge: {
      argumentType: ArgumentTypeName.Number,
      value: String(minAge),
    },
    signalHash: {
      argumentType: ArgumentTypeName.String,
      value: signalHash,
    },
    nameHash: {
      argumentType: ArgumentTypeName.String,
      value: computedNameHash,
    },
  }

  return anonAadhaarArgs
}
