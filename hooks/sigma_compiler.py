#!/usr/bin/env python3
"""Compile Sigma process_creation rules into a fast-lookup JSON database.

Parses YAML rules from the SigmaHQ repo, filters to Linux/macOS medium+ severity,
and outputs a JSON file optimized for the sigma_engine.py hook evaluator.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


SUPPORTED_FIELDS = {
    "CommandLine", "Image", "OriginalFileName",
    "User", "CurrentDirectory",
}

UNAVAILABLE_FIELDS = {
    "ParentImage", "ParentCommandLine", "ParentUser",
    "IntegrityLevel", "LogonId", "Hashes",
}

# Severity ordered strictest-first, so "at least this severe" is a <= on the
# rank. Shared by the per-rule filter and by main()'s output sort, which used to
# carry its own copy of this mapping.
LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DEFAULT_MIN_LEVEL = "medium"
DEFAULT_PRODUCTS = ("linux", "macos")

CONDITION_PATTERNS = [
    (r"^selection$", "single_selection"),
    (r"^all of selection[_*]*$", "all_selections"),
    (r"^1 of selection[_*]*$", "any_selection"),
    (r"^selection and not 1 of filter[_*]*$", "selection_minus_filters"),
    (r"^selection and not filter$", "selection_minus_filters"),
    (r"^all of selection[_*]* and not 1 of filter[_*]*$", "all_selections_minus_filters"),
    (r"^1 of selection[_*]* and not 1 of filter[_*]*$", "any_selection_minus_filters"),
    (r"^(selection_\w+) and (selection_\w+)$", "named_and"),
    (r"^(selection_\w+) and not (filter_\w+)$", "named_selection_minus_filter"),
    (r"^(selection_\w+) and not 1 of filter[_*]*$", "named_selection_minus_filters"),
    (r"^all of selection[_*]* and not filter[_*]*$", "all_selections_minus_filters"),
]


def parse_condition(condition_str):
    """Parse a sigma condition string into a structured type.

    Returns (condition_type, metadata_dict) or (None, None) if unparseable.
    """
    condition = condition_str.strip()

    for pattern, ctype in CONDITION_PATTERNS:
        match = re.match(pattern, condition)
        if match:
            meta = {}
            if match.groups():
                meta["groups"] = list(match.groups())
            return ctype, meta

    named_and_multi = re.match(
        r"^(selection_\w+(?:\s+and\s+selection_\w+)+)$", condition
    )
    if named_and_multi:
        names = re.findall(r"selection_\w+", condition)
        return "named_and_multi", {"selections": names}

    named_and_not = re.match(
        r"^(selection_\w+(?:\s+and\s+selection_\w+)*)\s+and\s+not\s+(.+)$",
        condition,
    )
    if named_and_not:
        sel_part = named_and_not.group(1)
        selections = re.findall(r"selection_\w+", sel_part)
        return "named_and_minus_filters", {"selections": selections}

    return None, None


def parse_modifier_chain(field_key):
    """Parse a sigma field key like 'CommandLine|contains|all' into components.

    Returns (field_name, modifiers_list).
    """
    parts = field_key.split("|")
    field_name = parts[0]
    modifiers = parts[1:] if len(parts) > 1 else []
    return field_name, modifiers


def compile_selection_entry(field_key, values):
    """Compile a single field entry within a selection.

    Returns dict with field, modifier, values, and contains_all flag.
    """
    field_name, modifiers = parse_modifier_chain(field_key)

    if not isinstance(values, list):
        values = [values]
    values = [str(v) for v in values]

    modifier = "contains"
    contains_all = False

    if "re" in modifiers:
        modifier = "re"
    elif "startswith" in modifiers:
        modifier = "startswith"
    elif "endswith" in modifiers:
        modifier = "endswith"
    elif "contains" in modifiers:
        modifier = "contains"
    elif not modifiers:
        modifier = "exact"

    if "all" in modifiers:
        contains_all = True

    return {
        "field": field_name,
        "modifier": modifier,
        "values": values,
        "all": contains_all,
    }


def compile_selection(selection_data):
    """Compile a selection block into a list of field conditions.

    A selection in sigma is a dict of field→values OR a list of such dicts.
    Within a single dict: fields are ANDed.
    A list of dicts: items are ORed.
    """
    if isinstance(selection_data, list):
        or_groups = []
        for item in selection_data:
            if isinstance(item, dict):
                group = [
                    compile_selection_entry(k, v)
                    for k, v in item.items()
                ]
                or_groups.append(group)
            else:
                or_groups.append([{
                    "field": "CommandLine",
                    "modifier": "contains",
                    "values": [str(item)],
                    "all": False,
                }])
        return {"type": "or_groups", "groups": or_groups}

    if isinstance(selection_data, dict):
        entries = [
            compile_selection_entry(k, v) for k, v in selection_data.items()
        ]
        return {"type": "and_fields", "entries": entries}

    return None


def uses_unavailable_fields(selection_data):
    """Check if a selection requires fields we can't provide."""
    if isinstance(selection_data, dict):
        for key in selection_data:
            field_name = key.split("|")[0]
            if field_name in UNAVAILABLE_FIELDS:
                return True
    elif isinstance(selection_data, list):
        for item in selection_data:
            if isinstance(item, dict):
                for key in item:
                    field_name = key.split("|")[0]
                    if field_name in UNAVAILABLE_FIELDS:
                        return True
    return False


def compile_rule(rule_data, min_level=DEFAULT_MIN_LEVEL, products=DEFAULT_PRODUCTS):
    """Compile a single sigma rule into the fast-lookup format.

    Returns compiled rule dict or None if rule should be skipped.

    ``min_level`` and ``products`` are parameters rather than the literals they
    used to be. ``main()`` accepts --min-level and --products, records both in
    the output metadata, and then filtered against a hardcoded medium/high/
    critical set and a hardcoded linux/macos pair regardless -- so
    ``--min-level critical`` emitted a file stamped ``"min_level": "critical"``
    that still contained every medium rule. The flag has to mean what the file
    says it means.
    """
    logsource = rule_data.get("logsource", {})
    if logsource.get("category") != "process_creation":
        return None

    product = logsource.get("product", "")
    if product not in products:
        return None

    level = rule_data.get("level", "low")
    if LEVEL_ORDER.get(level, 99) > LEVEL_ORDER.get(min_level, 99):
        return None

    detection = rule_data.get("detection", {})
    condition_str = detection.get("condition", "")
    if not condition_str:
        return None

    condition_type, condition_meta = parse_condition(condition_str)
    if condition_type is None:
        return None

    selections = {}
    filters = {}
    total_selection_keys = 0
    skipped_selection_keys = 0

    for key, value in detection.items():
        if key == "condition":
            continue
        if key.startswith("filter"):
            if not uses_unavailable_fields(value):
                compiled = compile_selection(value)
                if compiled:
                    filters[key] = compiled
        elif key.startswith("selection"):
            total_selection_keys += 1
            if uses_unavailable_fields(value):
                skipped_selection_keys += 1
                continue
            compiled = compile_selection(value)
            if compiled:
                selections[key] = compiled

    if not selections:
        return None

    if condition_type in ("all_selections", "all_selections_minus_filters"):
        if skipped_selection_keys > 0:
            return None

    tags = rule_data.get("tags", [])
    mitre_tags = [t for t in tags if t.startswith("attack.")]

    return {
        "id": rule_data.get("id", ""),
        "title": rule_data.get("title", "Unknown Rule"),
        "level": level,
        "description": rule_data.get("description", ""),
        "tags": mitre_tags,
        "references": rule_data.get("references", []),
        "selections": selections,
        "filters": filters,
        "condition_type": condition_type,
        "condition_meta": condition_meta or {},
        "condition_raw": condition_str,
    }


def find_rule_files(sigma_path, products):
    """Find all sigma rule YAML files for given products."""
    rule_files = []
    base = Path(sigma_path)

    search_dirs = [
        base / "rules",
        base / "rules-emerging-threats",
        base / "rules-threat-hunting",
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for product in products:
            product_dirs = list(search_dir.rglob(f"{product}/process_creation"))
            for pdir in product_dirs:
                rule_files.extend(pdir.rglob("*.yml"))

    return rule_files


def main():
    parser = argparse.ArgumentParser(description="Compile Sigma rules to JSON")
    parser.add_argument(
        "--sigma-path",
        required=True,
        help="Path to sigma rules repository root",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file path",
    )
    parser.add_argument(
        "--products",
        default="linux,macos",
        help="Comma-separated product list (default: linux,macos)",
    )
    parser.add_argument(
        "--min-level",
        default="medium",
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity level to include",
    )
    args = parser.parse_args()

    products = [p.strip() for p in args.products.split(",")]
    rule_files = find_rule_files(args.sigma_path, products)

    print(f"Found {len(rule_files)} rule files to process")

    compiled_rules = []

    for rule_file in sorted(rule_files):
        try:
            with open(rule_file) as f:
                rule_data = yaml.safe_load(f)
        except (yaml.YAMLError, OSError) as e:
            print(f"  SKIP (parse error): {rule_file}: {e}", file=sys.stderr)
            continue

        if not rule_data or not isinstance(rule_data, dict):
            continue

        compiled = compile_rule(rule_data, args.min_level, products)
        if compiled:
            compiled_rules.append(compiled)

    compiled_rules.sort(key=lambda r: LEVEL_ORDER.get(r["level"], 99))

    output = {
        "version": 1,
        "compiled_at": datetime.now(timezone.utc).isoformat(),
        "source": str(args.sigma_path),
        "products": products,
        "min_level": args.min_level,
        "rule_count": len(compiled_rules),
        "rules": compiled_rules,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Compiled {len(compiled_rules)} rules → {output_path}")
    print(f"  Critical: {sum(1 for r in compiled_rules if r['level'] == 'critical')}")
    print(f"  High: {sum(1 for r in compiled_rules if r['level'] == 'high')}")
    print(f"  Medium: {sum(1 for r in compiled_rules if r['level'] == 'medium')}")


if __name__ == "__main__":
    main()
