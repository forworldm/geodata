#!/usr/bin/env python3

import argparse
from pathlib import Path

import yaml


def parse_accelerated_domains(path: Path) -> set[str]:
    domains = set()

    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line.startswith("server=/"):
                domain = line[8:].split("/", 1)[0]
                domains.add(domain)

    return domains


def parse_chinamax(path: Path) -> set[str]:
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = set()

    for item in data.get("payload", []):
        if not isinstance(item, str):
            continue

        rule, _, value = item.partition(",")

        rule = rule.strip()
        value = value.strip()

        if rule == "DOMAIN":
            rules.add(f"full:{value}")
        elif rule == "DOMAIN-SUFFIX":
            rules.add(value)
        elif rule == "DOMAIN-KEYWORD":
            rules.add(f"keyword:{value}")
        elif rule == "DOMAIN-REGEX":
            rules.add(f"regexp:{value}")

    return rules


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("accelerated_domains")
    parser.add_argument("chinamax")
    parser.add_argument("output")
    args = parser.parse_args()

    accelerated = parse_accelerated_domains(Path(args.accelerated_domains))
    chinamax = parse_chinamax(Path(args.chinamax))

    result = sorted(accelerated & chinamax)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(result) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()