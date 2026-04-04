#!/usr/bin/env node

/**
 * Script to compile the ZK circuit.
 * Compiles the age-only verifier wrapper to R1CS, WASM, and witness calculator.
 *
 * Usage examples:
 *   node scripts/compile-circuit.js
 *   node scripts/compile-circuit.js --profile browser-prod --maxDataLength 1280
 *   node scripts/compile-circuit.js --dry-run
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { mkdir, writeFile, rm } from 'fs/promises';
import { existsSync } from 'fs';

const execAsync = promisify(exec);

// Circuit parameters
const CIRCUIT_NAME = 'aadhaar-age-verifier';
const BUILD_DIR = './build';
const BASE_CIRCUIT_PATH = './circuits/aadhaar-age-verifier.circom';
const GENERATED_WRAPPER_PATH = `./build/${CIRCUIT_NAME}.circom`;
const STALE_GENERATED_BASENAME = 'aadhaar-verifier.generated';

// RSA-2048 parameters
const N = 121;
const K = 17;
const DEFAULT_MAX_DATA_LENGTH = 1280;

const PROFILE_CONFIG = {
  dev: { optimization: '--O1', includeSym: true },
  'browser-prod': { optimization: '--O2', includeSym: false }
};

function parseArgs(argv) {
  const options = {
    profile: process.env.CIRCOM_PROFILE || 'browser-prod',
    maxDataLength: Number(process.env.MAX_DATA_LENGTH || DEFAULT_MAX_DATA_LENGTH),
    dryRun: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--profile' && argv[i + 1]) {
      options.profile = argv[i + 1];
      i += 1;
    } else if (arg.startsWith('--profile=')) {
      options.profile = arg.split('=')[1];
    } else if (arg === '--maxDataLength' && argv[i + 1]) {
      options.maxDataLength = Number(argv[i + 1]);
      i += 1;
    } else if (arg.startsWith('--maxDataLength=')) {
      options.maxDataLength = Number(arg.split('=')[1]);
    } else if (arg === '--dry-run') {
      options.dryRun = true;
    }
  }

  if (!PROFILE_CONFIG[options.profile]) {
    throw new Error(`Unsupported profile "${options.profile}". Use one of: ${Object.keys(PROFILE_CONFIG).join(', ')}`);
  }

  if (!Number.isInteger(options.maxDataLength) || options.maxDataLength < 1024 || options.maxDataLength > 4096) {
    throw new Error('maxDataLength must be an integer between 1024 and 4096');
  }

  return options;
}

async function generateWrapper(maxDataLength) {
  const wrapperSource = `pragma circom 2.1.9;

include "../circuits/aadhaar-age-verifier.circom";

component main { public [signalHash, nameHash] } = AadhaarAgeVerifier(${N}, ${K}, ${maxDataLength});
`;

  await writeFile(GENERATED_WRAPPER_PATH, wrapperSource, 'utf8');
}

async function cleanStaleArtifacts() {
  const staleTargets = [
    `${BUILD_DIR}/${STALE_GENERATED_BASENAME}.circom`,
    `${BUILD_DIR}/${STALE_GENERATED_BASENAME}.r1cs`,
    `${BUILD_DIR}/${STALE_GENERATED_BASENAME}.sym`,
    `${BUILD_DIR}/${STALE_GENERATED_BASENAME}_js`
  ];

  await Promise.all(
    staleTargets.map((target) => rm(target, { force: true, recursive: true }))
  );
}

async function compileCircuit() {
  console.log('🔧 Starting circuit compilation...\n');

  const options = parseArgs(process.argv.slice(2));
  const profile = PROFILE_CONFIG[options.profile];

  if (!existsSync(BUILD_DIR)) {
    await mkdir(BUILD_DIR, { recursive: true });
    console.log('✓ Created build directory');
  }

  if (!existsSync(BASE_CIRCUIT_PATH)) {
    console.error(`❌ Circuit file not found: ${BASE_CIRCUIT_PATH}`);
    process.exit(1);
  }

  await cleanStaleArtifacts();
  await generateWrapper(options.maxDataLength);

  const compileFlags = ['--r1cs', '--wasm', profile.optimization];
  if (profile.includeSym) compileFlags.push('--sym');

  const compileCmd = [
    '$HOME/.cargo/bin/circom',
    GENERATED_WRAPPER_PATH,
    ...compileFlags,
    '-l node_modules',
    `-o ${BUILD_DIR}`
  ].join(' ');

  console.log('📐 Compile profile:');
  console.log(`   - profile: ${options.profile}`);
  console.log(`   - optimization: ${profile.optimization}`);
  console.log(`   - maxDataLength: ${options.maxDataLength}`);
  console.log(`   - include .sym: ${profile.includeSym}`);
  console.log('');

  if (options.dryRun) {
    console.log('🧪 Dry run enabled. Compile command:');
    console.log(`   ${compileCmd}`);
    return;
  }

  try {
    console.log('⚙️  Compiling circuit (this may take a few minutes)...');
    const { stdout, stderr } = await execAsync(compileCmd, { shell: '/bin/bash', maxBuffer: 10 * 1024 * 1024 });

    if (stderr && !stderr.toLowerCase().includes('warning')) {
      console.error('Compilation warnings/errors:', stderr);
    }

    console.log('✓ Circuit compiled successfully');
    console.log(`✓ R1CS file: ${BUILD_DIR}/${CIRCUIT_NAME}.r1cs`);
    console.log(`✓ WASM file: ${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm`);
    console.log(`✓ Witness generator: ${BUILD_DIR}/${CIRCUIT_NAME}_js/`);

    console.log('\n📊 Circuit Stats:');
    console.log(stdout || '(No stats emitted by compiler)');

    console.log('\n✅ Circuit compilation complete!');
    console.log('\n📝 Next steps:');
    console.log('   1. Run: npm run setup:ceremony (to generate proving/verification keys)');
    console.log('   2. Run: npm run generate:proof (to test proof generation)');
  } catch (error) {
    console.error('\n❌ Compilation failed:', error.message);
    if (error.stdout) console.log('stdout:', error.stdout);
    if (error.stderr) console.log('stderr:', error.stderr);
    process.exit(1);
  }
}

compileCircuit().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
