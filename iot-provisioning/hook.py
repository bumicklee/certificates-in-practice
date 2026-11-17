"""사전 프로비저닝 훅 (로컬판). AWS IoT의 pre-provisioning hook Lambda와 입력·출력 모양이 같다.
입력: {claimCertificateId, certificateId, certificatePem, templateArn, clientId, parameters{...}}
출력: {allowProvisioning: bool, parameterOverrides: {...}}  (+ 로컬 로그용 reason)
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOW = os.path.join(HERE, "allowlist.json")
REG = os.path.join(HERE, "out/registry.json")


def _registry():
    return json.load(open(REG)) if os.path.exists(REG) else {}


def pre_provisioning_hook(event, context=None):
    serial = event.get("parameters", {}).get("SerialNumber", "")
    allow = set(json.load(open(ALLOW))["serials"])
    if serial not in allow:
        return {"allowProvisioning": False, "parameterOverrides": {}, "reason": f"serial {serial!r} not in allowlist"}
    if event.get("clientId") != serial:
        return {"allowProvisioning": False, "parameterOverrides": {},
                "reason": f"clientId {event.get('clientId')!r} != SerialNumber {serial!r}"}
    if serial in _registry():
        return {"allowProvisioning": False, "parameterOverrides": {},
                "reason": f"serial {serial!r} already provisioned as {_registry()[serial]['thingName']}"}
    return {"allowProvisioning": True, "parameterOverrides": {"ThingName": f"boiler-{serial}"}, "reason": "ok"}
