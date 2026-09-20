#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(pwd)"

cd "${1:-source}"

curl -L -O https://github.com/cokebar/gfwlist2dnsmasq/raw/refs/heads/master/gfwlist2dnsmasq.sh
chmod +x gfwlist2dnsmasq.sh && ./gfwlist2dnsmasq.sh -l -o data/gfw

curl -L -O https://github.com/felixonmars/dnsmasq-china-list/raw/refs/heads/master/accelerated-domains.china.conf
curl -L -O https://github.com/Accademia/Additional_Rule_For_Clash/raw/refs/heads/main/ChinaMax/ChinaMax.yaml

python3 "$repo_dir/geosite/make_china_list.py" \
    accelerated-domains.china.conf \
    ChinaMax.yaml \
    data/china-list

pushd data
for cnlist in ./*-cn; do
    sed -i 's/ @-!cn//' "$cnlist"
done
popd

go run ./ --outputname=geosite.dat --outputdir=..

cd "$repo_dir"

sha256sum geosite.dat > geosite.dat.sha256

count_rules() {
    awk '
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*#/ { next }
        { count++ }
        END { print count + 0 }
    ' "$1"
}

echo "Category rule counts:"
echo "  gfw:         $(count_rules source/data/gfw)"
echo "  china-list:  $(count_rules source/data/china-list)"
echo "SHA256:"
cat geosite.dat.sha256