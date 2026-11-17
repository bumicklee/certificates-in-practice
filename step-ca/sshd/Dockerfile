# 실습용 sshd. 비밀번호 로그인 없음, authorized_keys 없음. 사용자 CA가 서명한 인증서만 받는다.
FROM alpine:3.24.3
RUN apk add --no-cache openssh-server \
 && adduser -D -s /bin/sh alice && adduser -D -s /bin/sh bob \
 && passwd -u alice >/dev/null 2>&1; passwd -u bob >/dev/null 2>&1; ssh-keygen -A >/dev/null
COPY sshd_config /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd", "-D", "-e"]
