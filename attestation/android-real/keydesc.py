"""수업 9-2·9-3: Android 키 증명 확장(KeyDescription, OID 1.3.6.1.4.1.11129.2.1.17)을 읽는 작은 DER 파서.

스키마 출처: https://source.android.com/docs/security/features/keystore/attestation (KeyDescription v500)
열거값 출처: AOSP hardware/interfaces/security/keymint/aidl (KeyPurpose, Algorithm, KeyOrigin, Digest, EcCurve)

학습용이다. 실서비스는 https://github.com/android/keyattestation 같은 검증된 라이브러리를 쓰라고 Android 문서가 권한다.
"""
from cryptography import x509

KEYDESC_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
PROVINFO_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.30")

SECURITY_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
BOOT_STATE = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
PURPOSE = {0: "ENCRYPT", 1: "DECRYPT", 2: "SIGN", 3: "VERIFY", 5: "WRAP_KEY", 6: "AGREE_KEY", 7: "ATTEST_KEY"}
ALGORITHM = {1: "RSA", 3: "EC", 32: "AES", 33: "TRIPLE_DES", 128: "HMAC"}
ORIGIN = {0: "GENERATED", 1: "DERIVED", 2: "IMPORTED", 3: "RESERVED", 4: "SECURELY_IMPORTED"}
DIGEST = {0: "NONE", 1: "MD5", 2: "SHA1", 3: "SHA_2_224", 4: "SHA_2_256", 5: "SHA_2_384", 6: "SHA_2_512"}
EC_CURVE = {0: "P_224", 1: "P_256", 2: "P_384", 3: "P_521", 4: "CURVE_25519"}

# AuthorizationList 태그 → (이름, 종류). 종류: int, set, null, octets, str, rot, appid
TAGS = {
    1: ("purpose", "set"), 2: ("algorithm", "int"), 3: ("keySize", "int"), 4: ("blockMode", "set"),
    5: ("digest", "set"), 6: ("padding", "set"), 10: ("ecCurve", "int"), 11: ("mlDsaVariant", "int"),
    200: ("rsaPublicExponent", "int"), 203: ("mgfDigest", "set"), 303: ("rollbackResistance", "null"),
    305: ("earlyBootOnly", "null"), 400: ("activeDateTime", "int"), 401: ("originationExpireDateTime", "int"),
    402: ("usageExpireDateTime", "int"), 405: ("usageCountLimit", "int"), 503: ("noAuthRequired", "null"),
    504: ("userAuthType", "int"), 505: ("authTimeout", "int"), 506: ("allowWhileOnBody", "null"),
    507: ("trustedUserPresenceReq", "null"), 508: ("trustedConfirmationReq", "null"),
    509: ("unlockedDeviceReq", "null"), 701: ("creationDateTime", "int"), 702: ("origin", "int"),
    704: ("rootOfTrust", "rot"), 705: ("osVersion", "int"), 706: ("osPatchLevel", "int"),
    709: ("attestationApplicationId", "appid"), 710: ("attestationIdBrand", "str"),
    711: ("attestationIdDevice", "str"), 712: ("attestationIdProduct", "str"), 713: ("attestationIdSerial", "str"),
    714: ("attestationIdImei", "str"), 715: ("attestationIdMeid", "str"), 716: ("attestationIdManufacturer", "str"),
    717: ("attestationIdModel", "str"), 718: ("vendorPatchLevel", "int"), 719: ("bootPatchLevel", "int"),
    720: ("deviceUniqueAttestation", "null"), 723: ("attestationIdSecondImei", "str"), 724: ("moduleHash", "octets"),
}


def tlv(buf, i=0):
    """DER 한 덩어리를 읽는다 → (클래스, 구조형?, 태그 번호, 값 바이트, 다음 위치)."""
    b = buf[i]; i += 1
    cls, cons, tag = b >> 6, bool(b & 0x20), b & 0x1F
    if tag == 0x1F:                       # 높은 태그 번호(704 같은 값은 여러 바이트로 적힌다)
        tag = 0
        while True:
            b = buf[i]; i += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    ln = buf[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i:i + n], "big"); i += n
    return cls, cons, tag, buf[i:i + ln], i + ln


def children(buf):
    i, out = 0, []
    while i < len(buf):
        c = tlv(buf, i)
        out.append(c); i = c[4]
    return out


def _int(v): return int.from_bytes(v, "big", signed=True)


def _app_id(octets):
    # AttestationApplicationId ::= SEQUENCE { package_infos SET OF {package_name OCTET STRING, version INTEGER},
    #                                         signature_digests SET OF OCTET STRING }
    seq = children(tlv(octets)[3])
    pkgs = [(children(p[3])[0][3].decode(), _int(children(p[3])[1][3])) for p in children(seq[0][3])]
    digests = [d[3] for d in children(seq[1][3])]
    return {"packages": pkgs, "signatureDigests": digests}


def _authlist(buf):
    out = {}
    for cls, cons, tag, val, _ in children(buf):
        assert cls == 2, "AuthorizationList 원소는 문맥 태그여야 한다"
        name, kind = TAGS.get(tag, (f"tag{tag}", "raw"))
        inner = tlv(val)[3]                            # EXPLICIT 안쪽
        if kind == "int": out[name] = _int(inner)
        elif kind == "set": out[name] = sorted(_int(c[3]) for c in children(inner))
        elif kind == "null": out[name] = True
        elif kind == "str": out[name] = inner.decode(errors="replace")
        elif kind == "octets": out[name] = inner
        elif kind == "appid": out[name] = _app_id(inner)
        elif kind == "rot":
            k, locked, state, *h = children(inner)
            out[name] = {"verifiedBootKey": k[3], "deviceLocked": locked[3] != b"\x00",
                         "verifiedBootState": BOOT_STATE.get(_int(state[3]), _int(state[3])),
                         "verifiedBootHash": h[0][3] if h else None}
        else: out[name] = val
    return out


def parse_key_description(der: bytes) -> dict:
    f = children(tlv(der)[3])
    return {
        "attestationVersion": _int(f[0][3]),
        "attestationSecurityLevel": SECURITY_LEVEL.get(_int(f[1][3])),
        "keyMintVersion": _int(f[2][3]),
        "keyMintSecurityLevel": SECURITY_LEVEL.get(_int(f[3][3])),
        "attestationChallenge": f[4][3],
        "uniqueId": f[5][3],
        "softwareEnforced": _authlist(f[6][3]),
        "hardwareEnforced": _authlist(f[7][3]),
    }
