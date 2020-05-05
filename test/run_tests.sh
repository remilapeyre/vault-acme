#!/bin/sh
set -eu

trap 'cleanup' EXIT

cleanup()
{
    rc=$?
    if [ $rc -ne 0 ]; then
        cat test/pebble_challtestsrv.log
        cat test/pebble.log
    fi

    kill $(jobs -p) || true

    exit $rc
}

export PEBBLE_VA_NOSLEEP=1
export LEGO_NAMESERVER=127.0.0.1:8053
export EXEC_PROPAGATION_TIMEOUT=5
export EXEC_PATH=$PWD/test/test_dns.sh
export LEGO_CA_CERTIFICATES=$PWD/test/certs/pebble.minica.pem

pebble-challtestsrv -http01 "" -https01 "" -tlsalpn01 ""  > test/pebble_challtestsrv.log 2>&1 &
pebble -dnsserver 127.0.0.1:8053 > test/pebble.log 2>&1 &

set -x
go test "$@" ./acme | tee test/tests.log
set +x
