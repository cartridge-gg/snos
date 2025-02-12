#!/bin/sh

set -e

# Check if git is installed
if ! command -v git >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y git
fi

git clone https://github.com/dojoengine/dojo.git

SOZO_MIGRATOR_ADDRESS=0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d
SOZO_MIGRATOR_PRIVATE_KEY=0x7230b49615d175307d580c33d6fda61fc7b9aec91df0f5c1a5ebe3b8cbfee02

cd dojo/examples/spawn-and-move
sozo build && sozo migrate --account-address "${SOZO_MIGRATOR_ADDRESS}" --private-key "${SOZO_MIGRATOR_PRIVATE_KEY}" --rpc-url http://host.docker.internal:5050
