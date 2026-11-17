# 공통 값. 다른 스크립트가 source 한다.
NET=pki-lab-acme
SUBNET=10.30.0.0/24
WEB_IP=10.30.0.50
PEBBLE_IMG=ghcr.io/letsencrypt/pebble:2.10.1
CHALL_IMG=ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1
WEB_IMG=pki-lab-acme-web:nginx1.30.6-lego5.5.2
DIR=https://pebble:14000/dir
# 컨테이너 안에서 lego를 부르는 짧은 함수
lego_in_web() { docker exec -e LEGO_CA_CERTIFICATES=/etc/pebble/minica.pem pki-lab-acme-web lego "$@"; }
