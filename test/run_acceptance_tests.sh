#!/bin/sh
set -eu

trap 'cleanup' EXIT

cleanup()
{
    rc=$?
    if [ $rc -ne 0 ]; then
        cat test/vault.log
        cat test/pebble_challtestsrv.log
        cat test/pebble.log
    fi

    kill $(jobs -p) || true

    exit $rc
}

export VAULT_TOKEN=foo
export VAULT_ADDR=http://127.0.0.1:8200
export PEBBLE_VA_NOSLEEP=1
export LEGO_NAMESERVER=127.0.0.1:8053
export EXEC_PROPAGATION_TIMEOUT=5
export EXEC_PATH=$PWD/test/test_dns.sh
export LEGO_CA_CERTIFICATES=$PWD/test/certs/pebble.minica.pem

vault server -dev -config ./test/vault.hcl -dev-root-token-id "$VAULT_TOKEN" > test/vault.log 2>&1 &

pebble-challtestsrv -http01 "" -https01 "" -tlsalpn01 ""  > test/pebble_challtestsrv.log 2>&1 &
pebble -dnsserver 127.0.0.1:8053 > test/pebble.log 2>&1 &

vault write sys/plugins/catalog/secret/acme \
    sha256=$(sha256sum ./build/acme | cut -d ' ' -f 1) \
    command=acme

vault secrets enable acme

echo "Create an account"
vault write acme/accounts/lenstra \
	contact=remi@lenstra.fr \
	server_url=https://localhost:14000/dir \
	terms_of_service_agreed=true \
	provider=exec

echo "Create a role"
vault write acme/roles/lenstra.fr \
    account=lenstra \
    allowed_domains=lenstra.fr \
    allow_bare_domains=false \
    allow_subdomains=true

echo "Ask for a cert"
vault write acme/certs/lenstra.fr \
    common_name=www.lenstra.fr

echo "Ask for a cert and revoke it"
SECRET=$(vault write -format=json acme/certs/lenstra.fr common_name=lease.lenstra.fr)
STATUS_URL=$(printf '%s' $SECRET | jq -r '.data.url' | sed 's|14000/certZ|15000/cert-status-by-serial|')
LEASE_ID=$(printf '%s' $SECRET | jq -r '.lease_id')

curl -sk "$STATUS_URL" | grep -q Valid
vault lease revoke -sync "$LEASE_ID"
curl -sk "$STATUS_URL" | grep -q Revoked

echo "Getting a new cert should not take it from the cache"
SECRET=$(vault write -format=json acme/certs/lenstra.fr common_name=lease.lenstra.fr)
STATUS_URL=$(printf '%s' $SECRET | jq -r '.data.url' | sed 's|14000/certZ|15000/cert-status-by-serial|')
LEASE_ID=$(printf '%s' $SECRET | jq -r '.lease_id')

curl -sk "$STATUS_URL" | grep -q Valid

