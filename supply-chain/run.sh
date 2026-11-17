#!/usr/bin/env bash
# 31편 실습: 로컬 레지스트리 + cosign 키 쌍 서명·검증 (공개 Sigstore에 아무것도 올리지 않는다)
#
# 안전장치 두 겹
#   1) cosign sign --tlog-upload=false --use-signing-config=false  (Rekor·Fulcio·TSA를 쓰지 않음)
#   2) cosign 컨테이너는 바깥으로 못 나가는 --internal 네트워크에서만 돈다
set -uo pipefail
cd "$(dirname "$0")"
REG_IMG=registry:2.8.3
COSIGN=ghcr.io/sigstore/cosign/cosign:v3.1.3
NET=pki-lab-sc-net
HOSTREG=127.0.0.1:18491           # 내 PC(docker push)에서 보는 주소
INREG=pki-lab-registry:5000       # cosign 컨테이너에서 보는 주소(같은 레지스트리)

cleanup() { docker rm -f pki-lab-registry >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
[[ "${1:-}" == "--clean" ]] && { cleanup; echo "정리 끝"; exit 0; }

cosign() {  # 키 폴더만 마운트, 바깥 인터넷 없음, 빈 암호(실습 전용)
  docker run --rm --network $NET -e COSIGN_PASSWORD= -v "$PWD/keys:/keys" -w /keys $COSIGN "$@"
}
step() { echo; echo "## $*"; }
# 로컬 레지스트리에 올릴 때는 자격 증명 도우미가 없는 빈 설정을 쓴다(내 PC의 로그인 정보를 건드리지 않음)
DH=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
mkdir -p .docker && echo '{}' > .docker/config.json
dpush() { DOCKER_CONFIG="$PWD/.docker" DOCKER_HOST="$DH" docker push -q "$@"; }

cleanup
docker network create --internal $NET >/dev/null
docker run -d --name pki-lab-registry -p 127.0.0.1:18491:5000 $REG_IMG >/dev/null
docker network connect $NET pki-lab-registry
for i in $(seq 1 30); do curl -sf http://$HOSTREG/v2/ >/dev/null && break; sleep 0.3; done

step "1. 이미지 올리기: busybox:1.37.0 → $HOSTREG/lab/app:1.0"
docker tag busybox:1.37.0 $HOSTREG/lab/app:1.0
dpush $HOSTREG/lab/app:1.0
DIGEST=$(curl -sI -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json" \
  http://$HOSTREG/v2/lab/app/manifests/1.0 | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}' | tr -d '\r')
echo "digest: $DIGEST"

step "2. 키 쌍 두 개 만들기(release = 진짜 빌드 키, other = 다른 키)"
mkdir -p keys
for k in release other; do
  [[ -f keys/$k.key ]] || cosign generate-key-pair --output-key-prefix $k 2>&1 | grep -v -i password
done
ls keys

step "3. 서명: digest로, 투명성 로그 업로드 없이, 빌드 정보 주석 포함"
cosign sign --key /keys/release.key --tlog-upload=false --use-signing-config=false \
  --allow-http-registry -y -a builder=ci-main -a commit=FAKE-1a2b3c \
  $INREG/lab/app@$DIGEST 2>&1
echo "exit=$?"

step "4. 검증: 맞는 키"
cosign verify --key /keys/release.pub --insecure-ignore-tlog --allow-http-registry \
  $INREG/lab/app:1.0 2>&1 | sed 's/^\[{/\n[{/'
echo "exit=${PIPESTATUS[0]}"

step "5. 검증: 다른 키"
cosign verify --key /keys/other.pub --insecure-ignore-tlog --allow-http-registry $INREG/lab/app:1.0 2>&1 | tail -3
echo "exit=${PIPESTATUS[0]}"

step "6. 검증: 서명에 묶인 주석 정책 builder=ci-main (OK) / builder=laptop (거부)"
cosign verify --key /keys/release.pub --insecure-ignore-tlog --allow-http-registry -a builder=ci-main -o text $INREG/lab/app:1.0 >/dev/null 2>&1; echo "builder=ci-main exit=$?"
cosign verify --key /keys/release.pub --insecure-ignore-tlog --allow-http-registry -a builder=laptop $INREG/lab/app:1.0 2>&1 | tail -2
echo "builder=laptop exit=${PIPESTATUS[0]}"

step "7. 같은 태그 1.0에 다른 이미지를 다시 올린 뒤 검증"
docker build -q -t $HOSTREG/lab/app:1.0 tampered >/dev/null
dpush $HOSTREG/lab/app:1.0
DIGEST2=$(curl -sI -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json" \
  http://$HOSTREG/v2/lab/app/manifests/1.0 | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}' | tr -d '\r')
echo "태그 1.0의 새 digest: $DIGEST2"
cosign verify --key /keys/release.pub --insecure-ignore-tlog --allow-http-registry $INREG/lab/app:1.0 2>&1 | tail -3
echo "exit=${PIPESTATUS[0]}"
echo "원래 digest로 고정해 검증:"
cosign verify --key /keys/release.pub --insecure-ignore-tlog --allow-http-registry -o text $INREG/lab/app@$DIGEST >/dev/null 2>&1; echo "exit=$?"

step "8. 레지스트리에 생긴 서명 객체(태그 목록)"
curl -s http://$HOSTREG/v2/lab/app/tags/list; echo

cleanup
docker rmi -f $HOSTREG/lab/app:1.0 >/dev/null 2>&1
echo; echo "정리: 레지스트리 컨테이너·네트워크 삭제"
