pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "./helpers/signature.circom";
include "./helpers/extractor.circom";

/// @title AadhaarAgeVerifier
/// @notice Verifies Aadhaar QR signature and proves age threshold without photo/nullifier logic.
/// @param n RSA public key size per chunk
/// @param k Number of chunks the RSA public key is split into
/// @param maxDataLength Maximum length of the data
/// @input qrDataPadded QR data without the signature; assumes elements are bytes and remaining space is padded with 0
/// @input qrDataPaddedLength Length of padded QR data
/// @input delimiterIndices Indices of delimiters (255) in the QR text data
/// @input signature RSA signature
/// @input pubKey RSA public key (of the government)
/// @input minAge Minimum age threshold to prove against
/// @input public signalHash Any message to commit to (to make it part of the proof)
/// @output pubkeyHash Poseidon hash of the RSA public key
/// @output timestamp Timestamp of when the data was signed (Unix timestamp)
/// @output ageAboveMin Boolean flag indicating age is above or equal to minAge
/// @output minAgeUsed Revealed minAge threshold used for the proof
template AadhaarAgeVerifier(n, k, maxDataLength) {
    signal input qrDataPadded[maxDataLength];
    signal input qrDataPaddedLength;
    signal input delimiterIndices[18];
    signal input signature[k];
    signal input pubKey[k];
    signal input minAge;

    // Public input
    signal input signalHash;
    signal input nameHash;

    signal output pubkeyHash;
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
    component qrDataExtractor = IdentityAgeExtractor(maxDataLength);
    qrDataExtractor.data <== qrDataPadded;
    qrDataExtractor.qrDataPaddedLength <== qrDataPaddedLength;
    qrDataExtractor.delimiterIndices <== delimiterIndices;

    timestamp <== qrDataExtractor.timestamp;

    component packedName = PackBytes(64);
    packedName.in <== qrDataExtractor.nameBytes;

    component nameHasher = Poseidon(3);
    nameHasher.inputs <== packedName.out;
    nameHasher.out === nameHash;


    // Dummy square to prevent signal tampering (in rare cases where non-constrained inputs are ignored)
    signal signalHashSquare <== signalHash * signalHash;

    // Constrain minAge to byte range and compare extracted age against caller threshold.
    component minAgeBits = Num2Bits(8);
    minAgeBits.in <== minAge;

    // GreaterThan enforces strict `>`, so compare against (minAge - 1) to get `>=` semantics.
    component ageAboveMinChecker = GreaterThan(8);
    ageAboveMinChecker.in[0] <== qrDataExtractor.ageYears;
    ageAboveMinChecker.in[1] <== minAge - 1;
    ageAboveMin <== ageAboveMinChecker.out;
    minAgeUsed <== minAge;
}

