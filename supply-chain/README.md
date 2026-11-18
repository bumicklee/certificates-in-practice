# supply-chain (수업 10-1)

로컬 레지스트리 + cosign 키 쌍 서명·검증. 공개 Sigstore(Rekor·Fulcio·TSA)에는 아무것도 올리지 않는다.

- 이미지: `registry:2.8.3`(127.0.0.1:18491), `ghcr.io/sigstore/cosign/cosign:v3.1.3`, `busybox:1.37.0`
- 안전장치: `cosign sign --tlog-upload=false --use-signing-config=false`, 그리고 cosign 컨테이너는 `--internal` Docker 네트워크(`pki-lab-sc-net`)에서만 실행
- 확인하는 것: 맞는 키 OK / 다른 키 거부 / 주석 정책(`-a builder=...`) 불일치 거부 / 같은 태그를 다른 이미지로 덮어쓰면 거부, 원래 digest는 OK
- `docker push`는 자격 증명 도우미가 없는 빈 설정(`.docker/config.json`)으로 한다. 내 PC의 로그인 정보를 쓰지 않는다

## 실행
```bash
./run.sh            # 결과: ../results/21-cosign.txt. 끝나면 레지스트리·네트워크 삭제
./run.sh --clean    # 중간에 멈췄을 때 정리
rm -rf keys .docker # 키까지 지우기
```

키 없는 서명(`--certificate-identity`), `gh attestation verify`, npm provenance, policy-controller 정책은 강의에서 명령·설정만 보여 준다. 공개 서비스에 대고 실행하지 않는다.
