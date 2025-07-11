#!/bin/bash

set -e
set -x

WORKDIR=$(mktemp -d)

function cleanup {
    rm -rf ${WORKDIR}
}

trap cleanup EXIT

function retry_command {
    local -r cmd="$@"
    local -i attempt=0
    local -i max_attempts=5
    local -i sleep_time=5  # Initial backoff delay in seconds

    until $cmd; do
        attempt+=1
        if (( attempt > max_attempts )); then
            echo "The command has failed after $max_attempts attempts."
            return 1
        fi
        echo "The command has failed. Retrying in $sleep_time seconds..."
        sleep $sleep_time
        sleep_time=$((sleep_time * 2))  # Double the backoff delay each time
    done
}

function trivy_scan {
    # Perform trivy scans
    IMG=$(echo ${1} | sed 's/\//\-\-/g' | sed 's/:/\-\-/g')
    mkdir -p trivy
    retry_command trivy -f json -o trivy/${IMG}.json image ${1}
}

function grype_scan {
    # Perform grype scans
    IMG=$(echo ${1} | sed 's/\//\-\-/g' | sed 's/:/\-\-/g')
    mkdir -p grype
    retry_command grype -o json=grype/${IMG}.json ${1}
    cat grype/${IMG}.json
}

# Clone the github advisory database
git clone --depth=1  https://github.com/github/advisory-database.git

cat ./images.list

VERSION=$(date +%Y%m%d)
while read -r IMAGE; do
    echo "===== Processing ${IMAGE} =========================="
    trivy_scan ${IMAGE}
    grype_scan ${IMAGE}

    IMG=$(echo ${IMAGE} | sed 's/\//\-\-/g' | sed 's/:/\-\-/g')
    VERSION=$(date +%Y%m%d)

    sbcl --non-interactive --eval "(asdf:load-system :report)" --eval "(report:main)" $(pwd)/_site/${IMG}.html grype/${IMG}.json trivy/${IMG}.json ${IMAGE} || true

    find _site -name \*.html
done

sbcl --eval "(asdf:load-system :report)" --eval "(report::make-index.html)"
