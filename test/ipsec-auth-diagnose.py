#!/usr/bin/env python3
"""Classify private daemon logs in memory; output safe categories only."""
import json
import pathlib
import re
import sys

raw = sys.stdin.read() if sys.argv[1] == "-" else pathlib.Path(sys.argv[1]).read_text(errors="replace")
patterns = {
    "authenticationFailed": r"AUTHENTICATION_FAILED|authentication.*failed",
    "unsupportedEAP": r"unsupported EAP|EAP method.*not supported|EAP.*not.*supported",
    "eapFailure": r"EAP.*fail|MSCHAPV2.*fail",
    "eapSelected": r"EAP.*MSCHAPV2|MSCHAPV2.*EAP",
    "certificateTrustFailure": r"no trusted.*key|no issuer certificate|constraint check failed|certificate.*not trusted",
    "privateKeyMissing": r"no private key found",
    "noPeerConfig": r"no matching peer config|no IKE config",
    "timeout": r"giving up after|peer not responding",
    "md4Unavailable": r"(?:create|allocate).*MD4|MD4.*(?:not supported|not found|unavailable|failed)",
    "eapCredentialUnavailable": r"no EAP key|no shared key found|no EAP credentials",
    "mschapVerificationFailure": r"MSCHAPV2.*(?:verification failed|NT-Response.*invalid)",
    "dynamicMissing": r"loading EAP_DYNAMIC method failed",
    "dynamicInitiation": r"initiating EAP_DYNAMIC method failed",
    "mschapChallenge": r"initiating EAP_MSCHAPV2 method",
    "configuredPeer3": r"using configured EAP-Identity peer-3\.example\.invalid",
}
print(json.dumps({name: len(re.findall(pattern, raw, re.I)) for name, pattern in patterns.items()}))
