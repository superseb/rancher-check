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
  echo "ERR: Can't lookup ${STRIPPED_CATTLE_SERVER_NOPORT} using resolv.conf"
  echo "$(cat /etc/resolv.conf | grep -v ^#)"
  exit 1
fi

echo "OK: DNS for ${STRIPPED_CATTLE_SERVER_NOPORT} is ${DNS}"

# Checking ping endpoint (insecure)
PINGRESPONSE=$(curl -k -s -fL $CATTLE_SERVER/ping)
if [[ $PINGRESPONSE != "pong" ]]; then
  echo "ERR: Response from ${CATTLE_SERVER}/ping is not pong:"
  echo "$(curl -k -i -o - $CATTLE_SERVER/ping)"
  exit 1
else
  echo "OK: Response from ${CATTLE_SERVER}/ping is pong"
fi

TMPFILE=$(mktemp)
curl -k -s -fL $CATTLE_SERVER/v3/settings/cacerts | jq -r .value > $TMPFILE

CACHECKSUM=$(sha256sum $TMPFILE | awk '{print $1}')
echo "INFO: CA checksum from ${CATTLE_SERVER}/v3/settings/cacerts is $CACHECKSUM"

# Check if port is present in $STRIPPED_CATTLE_SERVER
if [[ $STRIPPED_CATTLE_SERVER = *":"* ]]; then
    OPENSSL_URL=$STRIPPED_CATTLE_SERVER
else
    OPENSSL_URL="${STRIPPED_CATTLE_SERVER}:443"
fi

# Check certificate chain
# From https://gist.github.com/hilbix/bde7c02009544faed7a1
while read -r line
do
    case "$line" in
    'Verify return code: 0 (ok)')   echo "OK: Certificate chain is complete";;
    'Verify return code: '*)    echo "ERR: Certificate chain is not complete" && export CERTCHAIN=1;;
    esac
done < <(echo | openssl s_client -CAfile $TMPFILE -connect $OPENSSL_URL -servername $STRIPPED_CATTLE_SERVER_NOPORT)

IFS=""
CERTTMPFILE=$(mktemp)
echo | openssl s_client -showcerts -CAfile $TMPFILE -connect $OPENSSL_URL -servername $STRIPPED_CATTLE_SERVER_NOPORT 2>/dev/null | openssl x509 -outform PEM > $CERTTMPFILE

rm -f $TMPFILE

# Get all CN/SANs and compare it with given FQDN
# https://stackoverflow.com/questions/20983217
# https://gist.github.com/stevenringo/2fe5000d8091f800aee4bb5ed1e800a6
CN=$(openssl x509 -in $CERTTMPFILE -noout -subject -nameopt multiline | awk '/commonName/ {print $NF}')
SANS=$(openssl x509 -in $CERTTMPFILE -noout -text|grep -oP '(?<=DNS:|IP Address:)[^,]+'|sort -uV)
echo "INFO: Found CN ${CN}"
if [[ -n $SANS ]]; then
  echo "INFO: Found SANS: ${SANS}"
fi
if [[ $CN = *"*"* ]]; then
  echo "OK: Wildcard certificate found (${CN})"
elif [[ $CN = *"${STRIPPED_CATTLE_SERVER_NOPORT}"* ]]; then
  echo "OK: ${STRIPPED_CATTLE_SERVER_NOPORT} is equal to ${CN}"
elif [[ $SANS = *"${STRIPPED_CATTLE_SERVER_NOPORT}"* ]]; then
  echo "OK: ${STRIPPED_CATTLE_SERVER_NOPORT} was found in ${SANS}"
else
  echo "ERR: ${STRIPPED_CATTLE_SERVER_NOPORT} was not found in CN or SANs"
fi

if [[ -n $CERTCHAIN ]]; then
  echo "Trying to get intermediates to complete chain and writing to /certs/fullchain.pem"
  echo "Note: this usually only works when using certificates signed by a recognized Certificate Authority"
  cert-chain-resolver -o /certs/fullchain.pem $CERTTMPFILE
fi

echo $(openssl x509 -inform pem -noout -text -certopt no_signame,no_pubkey,no_sigdump,no_aux,no_extensions -in $CERTTMPFILE)

rm -f $CERTTMPFILE
