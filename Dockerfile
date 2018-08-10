FROM alpine:3.7

RUN apk --no-cache --update add jq bind-tools curl openssl bash
COPY rancher-check.sh /usr/local/bin/rancher-check.sh

ENTRYPOINT [ "/usr/local/bin/rancher-check.sh" ]
