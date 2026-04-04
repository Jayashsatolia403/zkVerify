#!/usr/bin/env node

/**
 * ZK-Verify: Generate and Verify Proof for Aadhaar QR Code
 * 
 * This script:
 * 1. Reads an Aadhaar QR code from QR.png
 * 2. Generates zero-knowledge proof using the ZK-Verify API
 * 3. Verifies the proof
 * 
 * Usage:
 *   node scripts/generate-and-verify-proof.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as Jimp from 'jimp';
import QrCodeReader from 'qrcode-reader';
import { sha256Pad } from '@zk-email/helpers/dist/sha-utils.js';
import { Uint8ArrayToCharArray, bufferToHex } from '@zk-email/helpers/dist/binary-format.js';
import pako from 'pako';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const API_BASE_URL = 'http://localhost:3000';
const QR_IMAGE_PATH = path.join(__dirname, '..', 'QR.png');
const TEST_DATA_PATH = path.join(__dirname, '..', 'references/anon-aadhaar/packages/circuits/assets/dataInput.json');

// Get QR data from command line argument if provided
const QR_DATA_ARG = process.argv[2];
const DEFAULT_MIN_AGE = process.env.MIN_AGE ? parseInt(process.env.MIN_AGE, 10) : 21;
const MAX_DATA_LENGTH = 1280;

// ANSI colors for terminal output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
};

// Utility functions from lib/utils.ts

function convertBigIntToByteArray(bigInt) {
    const byteLength = Math.max(1, Math.ceil(bigInt.toString(2).length / 8));
    
    const result = new Uint8Array(byteLength);
    let i = 0;
    while (bigInt > 0n) {
        result[i] = Number(bigInt % 256n);
        bigInt = bigInt / 256n;
        i += 1;
    }
    return result.reverse();
}

function decompressByteArray(byteArray) {
    return pako.inflate(byteArray);
}

function splitToWords(number, wordsize, numberElement) {
    let t = number;
    const words = [];
    for (let i = 0n; i < numberElement; ++i) {
        const baseTwo = 2n;
        words.push(`${t % BigInt(Math.pow(Number(baseTwo), Number(wordsize)))}`);
        t = BigInt(t / BigInt(Math.pow(Number(2n), Number(wordsize))));
    }
    if (!(t === 0n)) {
        throw new Error(`Number ${number} does not fit in ${(wordsize * numberElement).toString()} bits`);
    }
    return words;
}

function printHeader(text) {
    console.log(`\n${colors.bright}${colors.blue}${'='.repeat(60)}${colors.reset}`);
    console.log(`${colors.bright}${colors.blue}${text.padStart((60 + text.length) / 2).padEnd(60)}${colors.reset}`);
    console.log(`${colors.bright}${colors.blue}${'='.repeat(60)}${colors.reset}\n`);
}

function printSuccess(text) {
    console.log(`${colors.green}✓ ${text}${colors.reset}`);
}

function printError(text) {
    console.log(`${colors.red}✗ ${text}${colors.reset}`);
}

function printInfo(text) {
    console.log(`${colors.yellow}ℹ ${text}${colors.reset}`);
}

function extractNameFromSignedData(signedData) {
    const delimiterIndices = [];
    for (let i = 0; i < signedData.length; i += 1) {
        if (signedData[i] === 255) {
            delimiterIndices.push(i);
            if (delimiterIndices.length === 4) break;
        }
    }

    if (delimiterIndices.length < 4) {
        throw new Error('Could not locate name field delimiters in signed QR data');
    }

    const nameBytes = signedData.slice(delimiterIndices[2] + 1, delimiterIndices[3]);
    return new TextDecoder().decode(nameBytes);
}

async function hashExpectedName(name) {
    const response = await fetch(`${API_BASE_URL}/api/verify/hash-name`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
    });

    if (!response.ok) {
        throw new Error(`Name hash API failed: HTTP ${response.status}`);
    }

    const body = await response.json();
    if (!body?.nameHash) {
        throw new Error('Name hash API returned invalid payload');
    }

    return body.nameHash;
}

/**
 * Read QR code from image file
 */
async function readQRCode(imagePath) {
    printInfo(`Reading QR code from: ${path.basename(imagePath)}`);
    
    try {
        const image = await Jimp.Jimp.read(imagePath);
        
        return new Promise((resolve, reject) => {
            const qr = new QrCodeReader();
            
            qr.callback = (err, value) => {
                if (err) {
                    reject(new Error(`Failed to decode QR: ${err.message}`));
                    return;
                }
                
                if (!value || !value.result) {
                    reject(new Error('No QR code data found'));
                    return;
                }
                
                printSuccess(`QR code read successfully (${value.result.length} characters)`);
                resolve(value.result);
            };
            
            qr.decode(image.bitmap);
        });
    } catch (error) {
        throw new Error(`Failed to read image: ${error.message}`);
    }
}

/**
 * Check if the ZK-Verify server is running
 */
async function checkServerStatus() {
    printInfo('Checking server status...');
    
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        if (response.ok) {
            printSuccess('Server is running');
            return true;
        } else {
            printError(`Server returned status code: ${response.status}`);
            return false;
        }
    } catch (error) {
        printError('Cannot connect to server. Please start the server with: npm start');
        return false;
    }
}

/**
 * Get circuit information from API
 */
async function getCircuitInfo() {
    printInfo('Fetching circuit information...');
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/proof/info`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const info = await response.json();
        
        printSuccess('Circuit info retrieved');
        console.log(`  Circuit: ${info.circuit || 'N/A'}`);
        console.log(`  Max Data Length: ${info.parameters?.maxDataLength || 'N/A'}`);
        console.log(`  Public Outputs: ${info.publicOutputs?.length || 0}`);
        
        return info;
    } catch (error) {
        printError(`Failed to get circuit info: ${error.message}`);
        return null;
    }
}

async function getProofKeyWords() {
    printInfo('Fetching proof key words...');
    const response = await fetch(`${API_BASE_URL}/api/proof/key`);
    if (!response.ok) {
        throw new Error(`Failed to fetch proof key words: HTTP ${response.status}`);
    }

    const body = await response.json();
    if (!Array.isArray(body?.pubKeyWords) || body.pubKeyWords.length !== 17) {
        throw new Error('Invalid pubKeyWords payload from API');
    }

    printSuccess('Proof key words retrieved');
    return body.pubKeyWords;
}

/**
 * Prepare circuit inputs from QR data
 */
function prepareCircuitInputs(qrData, pubKeyWords, minAge = DEFAULT_MIN_AGE) {
    printInfo('Preparing circuit inputs from QR data...');

    if (!Number.isInteger(minAge) || minAge < 0 || minAge > 120) {
        throw new Error('minAge must be an integer between 0 and 120');
    }

    try {
        // Decompress QR data
        const bigIntData = BigInt(qrData);
        const byteArray = convertBigIntToByteArray(bigIntData);
        const decompressedByteArray = decompressByteArray(byteArray);
        
        // Extract signature and signed data
        const signature = decompressedByteArray.slice(
            decompressedByteArray.length - 256,
            decompressedByteArray.length
        );
        
        const signedData = decompressedByteArray.slice(
            0,
            decompressedByteArray.length - 256
        );
        
        // Pad the message
        const [paddedMessage, messageLength] = sha256Pad(signedData, MAX_DATA_LENGTH);

        // Ensure the padded message is exactly maxDataLength bytes.
        const qrDataPadded = new Uint8Array(MAX_DATA_LENGTH);
        qrDataPadded.set(paddedMessage.slice(0, MAX_DATA_LENGTH));

        // Find delimiter indices
        const delimiterIndices = [];
        for (let i = 0; i < qrDataPadded.length; i++) {
            if (qrDataPadded[i] === 255) {
                delimiterIndices.push(i);
            }
            if (delimiterIndices.length === 18) {
                break;
            }
        }
        
        // Convert signature to BigInt
        const signatureBigint = BigInt('0x' + bufferToHex(Buffer.from(signature)).toString());
        
        const extractedName = extractNameFromSignedData(signedData);

        // Prepare circuit inputs
        const circuitInputs = {
            qrDataPadded: Uint8ArrayToCharArray(qrDataPadded),
            qrDataPaddedLength: messageLength.toString(),
            delimiterIndices: delimiterIndices.map(x => x.toString()),
            signature: splitToWords(signatureBigint, BigInt(121), BigInt(17)),
            pubKey: pubKeyWords,
            minAge: minAge.toString(),
            signalHash: '0'
        };

        printSuccess(`Circuit inputs prepared successfully (minAge=${minAge})`);
        return { circuitInputs, extractedName };

    } catch (error) {
        printError(`Error preparing inputs: ${error.message}`);
        throw error;
    }
}

/**
 * Generate zero-knowledge proof
 */
async function generateProof(circuitInputs) {
    printInfo('Generating zero-knowledge proof...');
    printInfo('This may take 1-5 seconds depending on hardware...');
    
    const startTime = Date.now();
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/proof/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ circuitInputs })
        });
        
        if (!response.ok) {
            const error = await response.text();
            throw new Error(`HTTP ${response.status}: ${error}`);
        }
        
        const result = await response.json();
        const generationTime = (Date.now() - startTime) / 1000;
        
        if (result.success) {
            printSuccess(`Proof generated successfully in ${generationTime.toFixed(2)}s`);
            return { proof: result.proof, publicSignals: result.publicSignals };
        } else {
            throw new Error(result.error || 'Unknown error');
        }
        
    } catch (error) {
        printError(`Error generating proof: ${error.message}`);
        return null;
    }
}

/**
 * Verify zero-knowledge proof
 */
async function verifyProof(proof, publicSignals) {
    printInfo('Verifying proof...');
    
    const startTime = Date.now();
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ proof, publicSignals })
        });
        
        if (!response.ok) {
            const error = await response.text();
            throw new Error(`HTTP ${response.status}: ${error}`);
        }
        
        const result = await response.json();
        const verificationTime = Date.now() - startTime;
        
        if (result.success && result.valid) {
            printSuccess(`Proof verified successfully in ${verificationTime.toFixed(2)}ms`);
            return result;
        } else {
            printError('Proof verification failed');
            return result;
        }
        
    } catch (error) {
        printError(`Error verifying proof: ${error.message}`);
        return null;
    }
}

/**
 * Display verified claims
 */
function displayClaims(claims) {
    printHeader('Verified Claims');
    
    console.log(`${colors.bright}Public Key Hash:${colors.reset} ${claims.pubkeyHash?.substring(0, 20)}...`);
    console.log(`${colors.bright}Timestamp:${colors.reset}       ${claims.timestamp}`);
    
    const ageAboveMin = claims.ageAboveMin;
    if (ageAboveMin !== null && ageAboveMin !== undefined) {
        const status = ageAboveMin ? `${colors.green}✓ YES${colors.reset}` : `${colors.red}✗ NO${colors.reset}`;
        const minAgeLabel = Number.isFinite(Number(claims.minAgeUsed)) ? ` (minAge=${claims.minAgeUsed})` : '';
        console.log(`${colors.bright}Age Above Configured Min${minAgeLabel}:${colors.reset}    ${status}`);
    } else {
        console.log(`${colors.bright}Age Above Configured Min:${colors.reset}    Not revealed`);
    }
}

/**
 * Display proof summary
 */
function displaySummary(proof, publicSignals) {
    printHeader('Proof Summary');
    
    const proofJson = JSON.stringify(proof);
    const proofSize = Buffer.byteLength(proofJson, 'utf8');
    
    const signalsJson = JSON.stringify(publicSignals);
    const signalsSize = Buffer.byteLength(signalsJson, 'utf8');
    
    console.log(`${colors.bright}Proof Size:${colors.reset}        ${proofSize} bytes`);
    console.log(`${colors.bright}Signals Size:${colors.reset}      ${signalsSize} bytes`);
    console.log(`${colors.bright}Total Size:${colors.reset}        ${proofSize + signalsSize} bytes`);
    console.log(`${colors.bright}Protocol:${colors.reset}          ${proof.protocol || 'groth16'}`);
    console.log(`${colors.bright}Curve:${colors.reset}             ${proof.curve || 'bn128'}`);
    console.log(`\n${colors.bright}Public Signals:${colors.reset}`);
    publicSignals.forEach((signal, i) => {
        let signalStr = String(signal);
        if (signalStr.length > 50) {
            signalStr = signalStr.substring(0, 47) + '...';
        }
        console.log(`  [${i}] ${signalStr}`);
    });
}

/**
 * Main execution function
 */
async function main() {
    try {
        printHeader('ZK-Verify: Aadhaar Age Verification POC');
        
        // Step 1: Check server
        if (!(await checkServerStatus())) {
            printError('\nPlease start the server first:');
            console.log('  cd /home/jayash/WebstormProjects/zkVerify/zkVerify');
            console.log('  npm start');
            process.exit(1);
        }
        
        // Step 2: Get circuit info
        const circuitInfo = await getCircuitInfo();
        if (!circuitInfo) {
            process.exit(1);
        }

        const pubKeyWords = await getProofKeyWords();

        // Step 3: Read QR code
        let qrData;
        
        // Priority: 1. Command line arg, 2. Read from QR.png, 3. Use test data
        if (QR_DATA_ARG) {
            printInfo('Using QR data from command line argument');
            qrData = QR_DATA_ARG;
            printSuccess(`QR data loaded (${qrData.length} characters)`);
        } else if (fs.existsSync(QR_IMAGE_PATH)) {
            try {
                qrData = await readQRCode(QR_IMAGE_PATH);
            } catch (error) {
                printError(`Failed to read QR from image: ${error.message}`);
                printInfo('Falling back to test data...');
                
                const testData = JSON.parse(fs.readFileSync(TEST_DATA_PATH, 'utf8'));
                qrData = testData.testQRData;
                printSuccess('Using test QR data');
            }
        } else {
            printInfo('QR.png not found, using test data...');
            const testData = JSON.parse(fs.readFileSync(TEST_DATA_PATH, 'utf8'));
            qrData = testData.testQRData;
            printSuccess('Using test QR data');
        }
        
        // Step 4: Prepare circuit inputs
        let circuitInputs;
        try {
            const prepared = prepareCircuitInputs(qrData, pubKeyWords, DEFAULT_MIN_AGE);
            const expectedName = process.env.EXPECTED_NAME ?? prepared.extractedName;
            printInfo(`Using expected name for hash binding: ${expectedName}`);
            const nameHash = await hashExpectedName(expectedName);
            circuitInputs = {
                ...prepared.circuitInputs,
                nameHash,
            };
        } catch (error) {
            printError('Failed to prepare circuit inputs');
            process.exit(1);
        }
        
        // Step 5: Generate proof
        printHeader('Proof Generation');
        const proofResult = await generateProof(circuitInputs);
        if (!proofResult) {
            process.exit(1);
        }
        
        const { proof, publicSignals } = proofResult;
        
        // Display proof summary
        displaySummary(proof, publicSignals);
        
        // Step 6: Verify proof
        printHeader('Proof Verification');
        const verificationResult = await verifyProof(proof, publicSignals);
        if (!verificationResult) {
            process.exit(1);
        }
        
        // Step 7: Display results
        if (verificationResult.claims) {
            displayClaims(verificationResult.claims);
        }
        
        // Final summary
        printHeader('Summary');
        if (verificationResult.valid) {
            printSuccess('✓ ZK proof generated and verified successfully!');
            console.log(`\n${colors.bright}What just happened?${colors.reset}`);
            console.log('  1. Your Aadhaar QR code was read from QR.png');
            console.log('  2. A zero-knowledge proof was generated proving you are above configured minimum age');
            console.log('  3. The proof was verified WITHOUT revealing your:');
            console.log('     • Date of birth');
            console.log('     • Name');
            console.log('     • Address');
            console.log('     • Aadhaar number');
            console.log('     • Photo');
            console.log(`\n${colors.green}Privacy-preserving identity verification complete!${colors.reset}`);
        } else {
            printError('Proof verification failed');
            process.exit(1);
        }
        
    } catch (error) {
        printError(`Unexpected error: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run the script
main();
