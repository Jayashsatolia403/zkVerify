pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "./helpers/signature.circom";
include "./helpers/extractor.circom";


/// @title AadhaarQRVerifier
/// @notice This circuit verifies the Aadhaar QR data using RSA signature
/// @param n RSA pubic key size per chunk
/// @param k Number of chunks the RSA public key is split into
/// @param maxDataLength Maximum length of the data
/// @input qrDataPadded QR data without the signature; assumes elements to be bytes; remaining space is padded with 0
/// @input qrDataPaddedLength Length of padded QR data
/// @input delimiterIndices Indices of delimiters (255) in the QR text data. 18 delimiters including photo
/// @input signature RSA signature
/// @input pubKey RSA public key (of the government)
/// @input minAge Minimum age threshold to prove against
/// @input nullifierSeed A random value used as an input to compute the nullifier; for example: applicationId, actionId
/// @input public signalHash Any message to commit to (to make it part of the proof)
/// @output pubkeyHash Poseidon hash of the RSA public key (after merging nearby chunks)
/// @output nullifier Fixed to 0 in age-only mode (nullifier/photo extraction disabled)
/// @output timestamp Timestamp of when the data was signed - extracted and converted to Unix timestamp
/// @output ageAboveMin Boolean flag indicating age is above minAge
/// @output minAgeUsed Revealed minAge threshold used for the proof
template AadhaarQRVerifier(n, k, maxDataLength) {
    signal input qrDataPadded[maxDataLength];
    signal input qrDataPaddedLength;
    signal input delimiterIndices[18];
    signal input signature[k];
    signal input pubKey[k];
    signal input minAge;

    // Public inputs
    signal input nullifierSeed;
    signal input signalHash;

    signal output pubkeyHash;
    signal output nullifier;
    signal output timestamp;
    signal output ageAboveMin;
    signal output minAgeUsed;


    // Assert `qrDataPaddedLength` fits in `ceil(log2(maxDataLength))`
    component n2bHeaderLength = Num2Bits(log2Ceil(maxDataLength));
    n2bHeaderLength.in <== qrDataPaddedLength;


    // Verify the RSA signature
    component signatureVerifier = SignatureVerifier(n, k, maxDataLength);
    signatureVerifier.qrDataPadded <== qrDataPadded;
    signatureVerifier.qrDataPaddedLength <== qrDataPaddedLength;
    signatureVerifier.pubKey <== pubKey;
    signatureVerifier.signature <== signature;
    pubkeyHash <== signatureVerifier.pubkeyHash;


    // Assert data between qrDataPaddedLength and maxDataLength is zero
    AssertZeroPadding(maxDataLength)(qrDataPadded, qrDataPaddedLength);
    

    // Extract age/timestamp claims from QR payload.
    component qrDataExtractor = QRDataExtractor(maxDataLength);
    qrDataExtractor.data <== qrDataPadded;
    qrDataExtractor.delimiterIndices <== delimiterIndices;

    timestamp <== qrDataExtractor.timestamp;

    // Nullifier is disabled in age-only mode to remove photo extraction and hashing constraints.
    nullifier <== 0;

    
    // Dummy square to prevent signal tampering (in rare cases where non-constrained inputs are ignored)
    signal signalHashSquare <== signalHash * signalHash;


    // Constrain minAge to byte range and compare extracted age against caller threshold.
    component minAgeBits = Num2Bits(8);
    minAgeBits.in <== minAge;

    component ageAboveMinChecker = GreaterThan(8);
    ageAboveMinChecker.in[0] <== qrDataExtractor.ageYears;
    ageAboveMinChecker.in[1] <== minAge;
    ageAboveMin <== ageAboveMinChecker.out;
    minAgeUsed <== minAge;
}

// Main component is intentionally defined in `circuits/aadhaar-verifier.circom`
// so build scripts can choose maxDataLength/profile-specific wrappers.
