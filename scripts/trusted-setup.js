#!/usr/bin/env node

/**
 * Script to perform trusted setup ceremony
 * Generates proving key (zkey) and verification key (vkey) from R1CS and Powers of Tau
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import * as snarkjs from 'snarkjs';

const execAsync = promisify(exec);

const CIRCUIT_NAME = 'aadhaar-age-verifier';
const BUILD_DIR = './build';
const R1CS_FILE = `${BUILD_DIR}/${CIRCUIT_NAME}.r1cs`;
const ZKEY_FILE = `${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey`;
const VKEY_FILE = `${BUILD_DIR}/verification_key.json`;

async function getConstraintCount(r1csFile) {
  const { stdout } = await execAsync(`node_modules/.bin/snarkjs r1cs info ${r1csFile}`)
  const match = stdout.match(/constraints:\s*(\d+)/i)
  if (!match) {
    throw new Error('Could not parse constraints from snarkjs r1cs info output')
  }
  return Number(match[1])
}

function minPtauPowerForConstraints(constraints) {
  let power = 1
  while (2 ** power < constraints) {
    power += 1
  }
  return power
}

function resolvePtauFile(requiredPower) {
  const forcedFile = process.env.PTAU_FILE
  if (forcedFile) return forcedFile

  const forcedPower = process.env.PTAU_POWER ? Number(process.env.PTAU_POWER) : undefined
  if (Number.isInteger(forcedPower) && forcedPower > 0) {
    return `${BUILD_DIR}/powersOfTau28_hez_final_${forcedPower}.ptau`
  }

  const availablePowers = []
  for (let power = 12; power <= 28; power += 1) {
    const candidate = `${BUILD_DIR}/powersOfTau28_hez_final_${power}.ptau`
    if (existsSync(candidate)) {
      availablePowers.push(power)
    }
  }

  const selectedPower = availablePowers.find(power => power >= requiredPower)
  if (selectedPower) {
    return `${BUILD_DIR}/powersOfTau28_hez_final_${selectedPower}.ptau`
  }

  return `${BUILD_DIR}/powersOfTau28_hez_final_${requiredPower}.ptau`
}

async function trustedSetup() {
  console.log('🔐 Starting trusted setup ceremony...\n');

  // Verify R1CS exists
  if (!existsSync(R1CS_FILE)) {
    console.error(`❌ R1CS file not found: ${R1CS_FILE}`);
    console.error('Run: npm run compile:circuit first');
    process.exit(1);
  }

  // Verify PTAU exists
  const constraints = await getConstraintCount(R1CS_FILE)
  const requiredPower = minPtauPowerForConstraints(constraints)
  const ptauFile = resolvePtauFile(requiredPower)

  console.log(`📏 Circuit constraints: ${constraints.toLocaleString()}`)
  console.log(`📦 Minimum PTAU power required: 2^${requiredPower}`)
  console.log(`📌 Using PTAU file: ${ptauFile}`)

  if (!existsSync(ptauFile)) {
    console.error(`❌ Powers of Tau file not found: ${ptauFile}`);
    console.error('The file should be downloaded automatically during setup.');
    process.exit(1);
  }

  try {
    // Step 1: Generate initial zkey
    console.log('⚙️  Step 1/3: Generating initial zkey (this will take several minutes)...');
    const zkey0 = `${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey`;

    // Remove stale outputs from previous failed ceremonies.
    await execAsync(`rm -f ${zkey0} ${ZKEY_FILE} ${VKEY_FILE}`)

    await snarkjs.zKey.newZKey(R1CS_FILE, ptauFile, zkey0);
    console.log('✓ Initial zkey generated');

    // Step 2: Contribute to ceremony (in production, this would be a multi-party ceremony)
    console.log('\n⚙️  Step 2/3: Contributing to ceremony...');
    const entropy = Math.random().toString() + Date.now().toString();
    
    await snarkjs.zKey.contribute(
      zkey0,
      ZKEY_FILE,
      'First contribution',
      entropy
    );
    console.log('✓ Contribution complete');

    // Step 3: Export verification key
    console.log('\n⚙️  Step 3/3: Exporting verification key...');
    const vKey = await snarkjs.zKey.exportVerificationKey(ZKEY_FILE);
    
    // Write verification key to file
    const fs = await import('fs/promises');
    await fs.writeFile(VKEY_FILE, JSON.stringify(vKey, null, 2));
    console.log('✓ Verification key exported');

    // Display file sizes
    console.log('\n📊 Generated Files:');
    const { stdout: zkeySize } = await execAsync(`du -h ${ZKEY_FILE}`);
    const { stdout: vkeySize } = await execAsync(`du -h ${VKEY_FILE}`);
    console.log(`   - Proving key: ${zkeySize.split('\t')[0]} (${ZKEY_FILE})`);
    console.log(`   - Verification key: ${vkeySize.split('\t')[0]} (${VKEY_FILE})`);

    // Verify the setup
    console.log('\n🔍 Verifying setup...');
    const isValid = await snarkjs.zKey.verifyFromR1cs(R1CS_FILE, ptauFile, ZKEY_FILE);

    if (isValid) {
      console.log('✅ Trusted setup verified successfully!\n');
      console.log('📝 Next steps:');
      console.log('   1. Create test data in test/ directory');
      console.log('   2. Run: npm run generate:proof (to test proof generation)');
      console.log('   3. Run: npm run verify:proof (to test proof verification)');
    } else {
      console.error('❌ Setup verification failed!');
      process.exit(1);
    }

    // Cleanup intermediate files
    console.log('\n🧹 Cleaning up intermediate files...');
    await execAsync(`rm -f ${zkey0}`);
    console.log('✓ Cleanup complete');

  } catch (error) {
    console.error('\n❌ Trusted setup failed:', error.message);
    if (String(error.message || '').includes('Missing section 1')) {
      console.error('Hint: this usually means a stale/corrupt intermediate zkey or mismatched PTAU power.')
      console.error('Try: delete build/*_0000.zkey and rerun setup with a higher PTAU (e.g. 21).')
    }
    if (error.stack) console.error(error.stack);
    process.exit(1);
  }
}

trustedSetup().catch(console.error);
