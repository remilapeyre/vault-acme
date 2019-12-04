#!/bin/sh
set -e

TAG=remilapeyre/vault-acme:build

echo Building $TAG
docker build -t "$TAG" . -f Dockerfile.build

echo Copying builds from $TAG
rm -rf ./build
docker container create --name extract "$TAG"
docker container cp extract:/go/src/github.com/remilapeyre/vault-acme/build/ ./build
docker container rm -f extract

echo Zipping builds from $TAG
find ./build -type d -maxdepth 1 -mindepth 1 -exec basename {} \; | xargs -I{} zip -j -r ./build/acme-plugin_{}.zip ./build/{} -i "*acme-plugin*"
find ./build -type d -maxdepth 1 -mindepth 1 -exec basename {} \; | xargs -I{} zip -j -r ./build/sidecar_{}.zip ./build/{} -i "*sidecar*"
