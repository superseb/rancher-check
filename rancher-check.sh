#!/bin/bash
if [[ $DEBUG == "true" ]]; then
  set -x
fi

# Check if tools exist
command -v jq >/dev/null 2>&1 || { echo "jq is not installed. Exiting." >&2; exit 1; }
command -v dig >/dev/null 2>&1 || { echo "dig is not installed. Exiting." >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is not installed. Exiting." >&2; exit 1; }
command -v sed >/dev/null 2>&1 || { echo "sed is not installed. Exiting." >&2; exit 1; }
command -v cat >/dev/null 2>&1 || { echo "cat is not installed. Exiting." >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is not installed. Exiting." >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is not installed. Exiting." >&2; exit 1; }

# Check if server-url is given
if [ -z "$1" ]; then
    echo "Usage: $0 server-url"
    exit 1
fi

CATTLE_SERVER=$1
STRIPPED_CATTLE_SERVER=$(echo $CATTLE_SERVER | sed -e 's/^http:\/\///g' -e 's/^https:\/\///g')
STRIPPED_CATTLE_SERVER_NOPORT=$(echo $STRIPPED_CATTLE_SERVER | sed -e 's/:.*//')

# Check DNS
DNS=$(dig $STRIPPED_CATTLE_SERVER_NOPORT +short)
if [[ $DNS == "" ]]; then
  echo "Can't lookup ${STRIPPED_CATTLE_SERVER_NOPORT} using resolv.conf"
  echo "$(cat /etc/resolv.conf | grep -v ^#)"
  exit 1
fi

echo "DNS for ${STRIPPED_CATTLE_SERVER_NOPORT} is ${DNS}"

# Checking ping endpoint (insecure)
PINGRESPONSE=$(curl -k -s -fL $CATTLE_SERVER/ping)
if [[ $PINGRESPONSE != "pong" ]]; then
  echo "Response from ${CATTLE_SERVER}/ping is not pong:"
  echo "$(curl -k -i -o - $CATTLE_SERVER/ping)"
  exit 1
fi

# Check certificate chain
TMPFILE=$(mktemp)
curl -k -s -fL $CATTLE_SERVER/v3/settings/cacerts | jq -r .value > $TMPFILE

CACHECKSUM=$(sha256sum $TMPFILE | awk '{print $1}')
echo "CA checksum from ${CATTLE_SERVER}/v3/settings/cacerts is $CACHECKSUM"

# From https://gist.github.com/hilbix/bde7c02009544faed7a1
# Check if port is present in $STRIPPED_CATTLE_SERVER
if [[ $STRIPPED_CATTLE_SERVER = *":"* ]]; then
    OPENSSL_URL=$STRIPPED_CATTLE_SERVER
else
    OPENSSL_URL="${STRIPPED_CATTLE_SERVER}:443"
fi

while read -r line
do
    case "$line" in
    'Verify return code: 0 (ok)')   echo "Certificate chain is complete";;
    'Verify return code: '*)    echo "Certificate chain is not complete";;
    esac
done < <(echo | openssl s_client -CAfile $TMPFILE -connect $OPENSSL_URL -servername $STRIPPED_CATTLE_SERVER_NOPORT)

CERTTMPFILE=$(mktemp)
echo | openssl s_client -showcerts -CAfile $TMPFILE -connect $OPENSSL_URL -servername $STRIPPED_CATTLE_SERVER_NOPORT 2>/dev/null | openssl x509 -outform PEM > $CERTTMPFILE

rm -f $TMPFILE

IFS=""
echo $(openssl x509 -inform pem -noout -text -certopt no_signame,no_pubkey,no_sigdump,no_aux,no_extensions < $CERTTMPFILE)
echo $(openssl x509 -inform pem -noout -text < $CERTTMPFILE | grep -A1 "Subject Alternative Name")

rm -f $CERTTMPFILE
