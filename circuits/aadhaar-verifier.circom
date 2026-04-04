pragma circom 2.1.9;

include "./aadhaar-age-verifier.circom";

// Canonical entrypoint used by build scripts when no custom wrapper is generated.
component main { public [signalHash, nameHash] } = AadhaarAgeVerifier(121, 17, 1280);
