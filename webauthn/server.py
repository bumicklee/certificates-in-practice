"""수업 9-5 실습: localhost WebAuthn 서버 (py_webauthn).

RP ID = localhost, 허용 출처 = http://localhost:18490 하나뿐.
127.0.0.1:18490에만 묶는다. 저장소는 메모리(재시작하면 사라짐).
"""
import secrets

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
import json

RP_ID = "localhost"
RP_NAME = "FAKE Shop (lab)"
ORIGIN = "http://localhost:18490"

app = FastAPI()
USERS: dict[str, dict] = {}        # user_name -> {"id": bytes, "creds": {cred_id: {...}}}
CHALLENGES: dict[str, bytes] = {}  # "reg:<user>" / "auth:<user>" -> challenge (한 번 쓰면 지운다)


@app.post("/register/options")
def register_options(body: dict):
    name = body["user_name"]
    user = USERS.setdefault(name, {"id": secrets.token_bytes(16), "creds": {}})
    opts = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=name,
        user_id=user["id"],
        attestation=AttestationConveyancePreference.NONE,  # 일반 서비스는 증명 없이
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    CHALLENGES["reg:" + name] = opts.challenge
    return JSONResponse(json.loads(options_to_json(opts)))


@app.post("/register/verify")
def register_verify(body: dict):
    name = body["user_name"]
    challenge = CHALLENGES.pop("reg:" + name, None)
    if challenge is None:
        raise HTTPException(400, "no pending challenge")
    try:
        v = verify_registration_response(
            credential=body["credential"],
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except Exception as e:  # InvalidRegistrationResponse 등
        raise HTTPException(400, f"{type(e).__name__}: {e}")
    USERS[name]["creds"][v.credential_id] = {
        "public_key": v.credential_public_key,
        "sign_count": v.sign_count,
    }
    return {"ok": True, "fmt": v.fmt, "credential_id_len": len(v.credential_id),
            "aaguid": v.aaguid, "uv": v.user_verified}


@app.post("/login/options")
def login_options(body: dict):
    name = body["user_name"]
    user = USERS.get(name)
    if not user:
        raise HTTPException(404, "unknown user")
    opts = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c) for c in user["creds"]],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    CHALLENGES["auth:" + name] = opts.challenge
    return JSONResponse(json.loads(options_to_json(opts)))


@app.post("/login/verify")
def login_verify(body: dict):
    from webauthn.helpers import base64url_to_bytes
    name = body["user_name"]
    challenge = CHALLENGES.pop("auth:" + name, None)  # 실패해도 챌린지는 버린다(재사용 금지)
    if challenge is None:
        raise HTTPException(400, "no pending challenge")
    cred = body["credential"]
    stored = USERS[name]["creds"].get(base64url_to_bytes(cred["rawId"]))
    if stored is None:
        raise HTTPException(400, "unknown credential")
    try:
        v = verify_authentication_response(
            credential=cred,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=stored["public_key"],
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(400, f"{type(e).__name__}: {e}")
    stored["sign_count"] = v.new_sign_count
    return {"ok": True, "user": name, "new_sign_count": v.new_sign_count}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=18490, log_level="warning")
