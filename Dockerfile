FROM alpine:3.7

RUN apk --no-cache --update add jq bind-tools curl openssl bash util-linux coreutils binutils findutils grep
RUN mkdir /lib64 /certs && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
RUN curl -sLf https://github.com/zakjan/cert-chain-resolver/releases/download/1.0.2/cert-chain-resolver_linux_amd64.tar.gz | tar xvzf - -C /usr/bin --strip 1 && chmod +x /usr/bin/cert-chain-resolver
COPY rancher-check.sh /usr/local/bin/rancher-check.sh

ENTRYPOINT [ "/usr/local/bin/rancher-check.sh" ]
