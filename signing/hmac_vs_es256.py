"""HS256(공유 비밀) vs ES256(공개키): '검증만 하는 서비스'가 토큰을 위조할 수 있나(수업 3-3).

등장인물
  auth    : 토큰을 발급하는 인증 서버
  orders  : 토큰을 검증만 하는 서비스. 이 서비스가 털렸다고 가정한다.

    ../.venv/bin/python hmac_vs_es256.py
"""
import time, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

now = int(time.time())
claims = lambda sub, role: {"sub": sub, "role": role, "iat": now, "exp": now + 600}

print("== HS256: auth와 orders가 같은 비밀을 나눠 가진다")
SECRET = "FAKE-shared-secret-0123456789abcdef"          # 두 서비스 설정에 같은 값
real = jwt.encode(claims("user-1001", "user"), SECRET, algorithm="HS256")
# orders가 가진 것: SECRET. 검증에 쓰는 값이 곧 서명에 쓰는 값이다.
forged = jwt.encode(claims("user-0001", "admin"), SECRET, algorithm="HS256")
for name, t in (("auth가 만든 토큰", real), ("orders가 만든 위조 토큰", forged)):
    c = jwt.decode(t, SECRET, algorithms=["HS256"])
    print(f"  {name:<22} -> 통과 sub={c['sub']} role={c['role']}")

print("== ES256: auth만 개인키, orders는 공개키만")
priv = ec.generate_private_key(ec.SECP256R1())
pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
real = jwt.encode(claims("user-1001", "user"), priv, algorithm="ES256")
c = jwt.decode(real, pub_pem, algorithms=["ES256"])
print(f"  auth가 만든 토큰            -> 통과 sub={c['sub']} role={c['role']}")
# orders가 가진 것: 공개키뿐. 공개키로 서명을 시도하면?
try:
    jwt.encode(claims("user-0001", "admin"), pub_pem, algorithm="ES256")
    print("  공개키로 ES256 서명        -> 됨(?)")
except Exception as e:
    print(f"  공개키로 ES256 서명        -> 불가 (공개키 객체에는 sign이 없다: {type(e).__name__})")
# 옛 '알고리즘 혼동' 공격: 공개키 PEM을 HMAC 비밀처럼 써서 HS256으로 서명
try:
    t = jwt.encode(claims("user-0001", "admin"), pub_pem, algorithm="HS256")
except Exception as e:
    print(f"  공개키를 HS256 비밀로 서명  -> 라이브러리가 거부 {type(e).__name__}")
other = ec.generate_private_key(ec.SECP256R1())
t = jwt.encode(claims("user-0001", "admin"), other, algorithm="ES256")
try:
    jwt.decode(t, pub_pem, algorithms=["ES256"])
except Exception as e:
    print(f"  다른 개인키로 만든 위조 토큰 -> 실패 {type(e).__name__}")
