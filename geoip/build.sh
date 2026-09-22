#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(pwd)"

cd "${1:-source}"

mkdir -p ./ipinfo
curl -L "https://ipinfo.io/data/ipinfo_lite.csv.gz?_src=frontend&token=$IPINFO_TOKEN" \
    -o ./ipinfo/ipinfo_lite.csv.gz

go run ./ -c ./config.json

cp ./output/geoip.dat "$repo_dir"

cd "$repo_dir"
sha256sum geoip.dat > geoip.dat.sha256
