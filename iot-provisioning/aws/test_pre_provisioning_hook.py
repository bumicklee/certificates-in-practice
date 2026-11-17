"""AWS 없이 도는 훅 단위 시험.  ../../.venv/bin/python -m unittest -v test_pre_provisioning_hook"""
import unittest
import pre_provisioning_hook as hook

ARN = "arn:aws:iot:ap-northeast-2:111122223333:provisioningtemplate/boiler-template"


class CondFail(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeTable:
    """DynamoDB update_item의 조건식 '#s = :m'만 흉내 낸다."""
    def __init__(self, items): self.items = {i["serial"]: dict(i) for i in items}

    def update_item(self, Key, ExpressionAttributeValues, **_):
        it = self.items.get(Key["serial"])
        if not it or it["status"] != ExpressionAttributeValues[":m"]:
            raise CondFail()
        it["status"] = ExpressionAttributeValues[":p"]; it["certificateId"] = ExpressionAttributeValues[":c"]


def ev(serial, client=None, claim="claimcert-line1", arn=ARN):
    return {"claimCertificateId": claim, "certificateId": "c0ffee", "certificatePem": "-----BEGIN CERTIFICATE-----…",
            "templateArn": arn, "clientId": client or serial, "parameters": {"SerialNumber": serial}}


class HookTest(unittest.TestCase):
    def setUp(self):
        hook._tbl = FakeTable([{"serial": "SN-0000-0001", "status": "manufactured"},
                               {"serial": "SN-0000-0002", "status": "manufactured"}])
        hook.ALLOWED_CLAIMS = {"claimcert-line1"}

    def test_allow_known_serial(self):
        self.assertEqual(hook.handler(ev("SN-0000-0001"), None), {"allowProvisioning": True, "parameterOverrides": {}})

    def test_deny_unknown_serial(self):
        self.assertFalse(hook.handler(ev("SN-0000-0099"), None)["allowProvisioning"])

    def test_deny_duplicate(self):
        self.assertTrue(hook.handler(ev("SN-0000-0002"), None)["allowProvisioning"])
        self.assertFalse(hook.handler(ev("SN-0000-0002"), None)["allowProvisioning"])

    def test_deny_clientid_mismatch(self):
        self.assertFalse(hook.handler(ev("SN-0000-0001", client="SN-0000-0002"), None)["allowProvisioning"])

    def test_deny_disabled_claim(self):
        self.assertFalse(hook.handler(ev("SN-0000-0001", claim="claimcert-leaked"), None)["allowProvisioning"])

    def test_deny_other_template(self):
        self.assertFalse(hook.handler(ev("SN-0000-0001", arn=ARN.replace("boiler", "other")), None)["allowProvisioning"])

    def test_output_has_required_keys(self):
        for e in (ev("SN-0000-0001"), ev("SN-0000-0099")):
            self.assertEqual(set(hook.handler(e, None)), {"allowProvisioning", "parameterOverrides"})


if __name__ == "__main__":
    unittest.main()
