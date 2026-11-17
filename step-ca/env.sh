NET=pki-lab-step
STEP_CLI=smallstep/step-cli:0.31.0
STEP_CA=smallstep/step-ca:0.30.2
LEGO=goacme/lego:v5.5.2
SSHD_BASE=alpine:3.24.3
# step CLI를 이 폴더(out/)를 작업 디렉터리로 해서 부른다
step_cli() { docker run --rm -v "$PWD/out:/work" -w /work -e STEPPATH=/work/stepca "$@"; }
