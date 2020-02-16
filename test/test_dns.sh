#!/bin/sh
set -eu

payload="{\"host\": \"$2\", \"value\": \"$3\"}"

if [ "$1" = "present" ]
then
    curl --silent -X POST -d "$payload" http://localhost:8055/set-txt
elif [ "$1" = "cleanup" ]
then
    curl --silent -X POST -d "$payload" http://localhost:8055/clear-txt
fi
