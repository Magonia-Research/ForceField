#!/usr/bin/env python3
"""Sigma-based security guard hook for Claude Code.

Evaluates Bash commands against compiled Sigma process_creation rules. On match,
returns an "ask" decision so the user can approve or deny -- never a hard "deny",
because SigmaHQ rules are broad heuristics and a hard block on them would break
Portcullis' zero-false-positive-deny guarantee. The tiered config may downgrade
the "ask" to a non-blocking "warn" and may raise the severity floor so fewer
rules fire (see hooks/config.py).

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)
"""

import json
import os
import re
import sys
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hook_logging import clamp_and_emit  # noqa: E402

RULES_PATH = Path(__file__).parent / "sigma_rules.json"

# Severity rank for the runtime floor (higher == more severe). Distinct from the
# compiler's inverted sort order; used only to drop rules below the config floor.
_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _severity_floor_rank():
    """Runtime Sigma severity floor as a rank; ``medium`` (1) on any error.

    Lets the tiered config quiet Sigma (permissive preset -> ``high``) without a
    recompile. With no config the floor is ``medium``, so every compiled
    (medium+) rule stays active and shipped behavior is unchanged.
    """
    try:
        from config import resolve_severity_floor
        return _LEVEL_RANK.get(resolve_severity_floor("sigma_engine"), 1)
    except Exception:
        return 1


@lru_cache(maxsize=512)
def compile_re(pattern):
    """Compile and cache regex patterns."""
    return re.compile(pattern, re.IGNORECASE)


def load_rules():
    """Load compiled sigma rules from JSON."""
    if not RULES_PATH.exists():
        return []
    with open(RULES_PATH) as f:
        data = json.load(f)
    return data.get("rules", [])


def extract_image(command):
    """Extract approximate 'Image' (binary path) from command string.

    Heuristic: take the first token, skip prefixes like sudo/env.
    If the token is already a path, use it as-is.
    If it's a bare name like 'curl', prepend '/' so Image|endswith: '/curl' works.
    """
    tokens = command.split()
    skip_prefixes = {"sudo", "env", "nice", "nohup", "timeout", "strace"}

    for token in tokens:
        if "=" in token and token.index("=") < len(token) - 1:
            continue
        base = os.path.basename(token)
        if base in skip_prefixes:
            continue
        if token.startswith("/"):
            return token
        return "/" + base

    return "/" + tokens[0] if tokens else ""


def match_field_value(field_value, modifier, values, all_required):
    """Check if field_value matches using the given modifier and values.

    For 'all' modifier: ALL values must match (AND).
    Otherwise: ANY value must match (OR).
    """
    if field_value is None:
        return False

    check_value = field_value.lower()

    if all_required:
        for v in values:
            v_lower = v.lower()
            if modifier == "contains":
                if v_lower not in check_value:
                    return False
            elif modifier == "startswith":
                if not check_value.startswith(v_lower):
                    return False
            elif modifier == "endswith":
                if not check_value.endswith(v_lower):
                    return False
            elif modifier == "re":
                try:
                    if not compile_re(v).search(field_value):
                        return False
                except re.error:
                    return False
            elif modifier == "exact":
                if check_value != v_lower:
                    return False
        return True

    for v in values:
        v_lower = v.lower()
        if modifier == "contains":
            if v_lower in check_value:
                return True
        elif modifier == "startswith":
            if check_value.startswith(v_lower):
                return True
        elif modifier == "endswith":
            if check_value.endswith(v_lower):
                return True
        elif modifier == "re":
            try:
                if compile_re(v).search(field_value):
                    return True
            except re.error:
                continue
        elif modifier == "exact":
            if check_value == v_lower:
                return True

    return False


def get_field_value(field_name, command, image):
    """Map sigma field name to actual value from our context."""
    if field_name == "CommandLine":
        return command
    if field_name in ("Image", "OriginalFileName"):
        return image
    if field_name == "CurrentDirectory":
        return os.getcwd()
    if field_name == "User":
        return os.environ.get("USER", "")
    return None


def evaluate_selection(selection, command, image):
    """Evaluate a single compiled selection against the command.

    Returns True if the selection matches.
    """
    sel_type = selection.get("type")

    if sel_type == "and_fields":
        for entry in selection["entries"]:
            field_value = get_field_value(entry["field"], command, image)
            if field_value is None:
                return False
            if not match_field_value(
                field_value, entry["modifier"], entry["values"], entry["all"]
            ):
                return False
        return True

    if sel_type == "or_groups":
        for group in selection["groups"]:
            group_match = True
            for entry in group:
                field_value = get_field_value(entry["field"], command, image)
                if field_value is None:
                    group_match = False
                    break
                if not match_field_value(
                    field_value, entry["modifier"], entry["values"], entry["all"]
                ):
                    group_match = False
                    break
            if group_match:
                return True
        return False

    return False


def evaluate_rule(rule, command, image):
    """Evaluate a single rule against the command.

    Returns True if the rule triggers (selection matches and filters don't suppress).
    """
    selections = rule.get("selections", {})
    filters = rule.get("filters", {})
    condition_type = rule.get("condition_type", "")
    condition_meta = rule.get("condition_meta", {})

    if not selections:
        return False

    sel_results = {}
    for name, sel_data in selections.items():
        sel_results[name] = evaluate_selection(sel_data, command, image)

    filter_results = {}
    for name, flt_data in filters.items():
        filter_results[name] = evaluate_selection(flt_data, command, image)

    selection_match = False

    if condition_type == "single_selection":
        sel_key = next(
            (k for k in sel_results if k.startswith("selection")), None
        )
        selection_match = sel_results.get(sel_key, False) if sel_key else False

    elif condition_type == "all_selections":
        if sel_results:
            selection_match = all(sel_results.values())
        else:
            selection_match = False

    elif condition_type == "any_selection":
        selection_match = any(sel_results.values())

    elif condition_type in (
        "selection_minus_filters",
        "all_selections_minus_filters",
    ):
        if condition_type == "all_selections_minus_filters":
            selection_match = all(sel_results.values()) if sel_results else False
        else:
            sel_key = next(
                (k for k in sel_results if k.startswith("selection")), None
            )
            selection_match = sel_results.get(sel_key, False) if sel_key else False

    elif condition_type == "any_selection_minus_filters":
        selection_match = any(sel_results.values())

    elif condition_type == "named_and":
        groups = condition_meta.get("groups", [])
        selection_match = all(sel_results.get(g, False) for g in groups) if groups else False

    elif condition_type in ("named_and_multi", "named_and_minus_filters"):
        # "named_and_minus_filters" is "sel_a and sel_b and not filter": the
        # filter half is applied by the global suppression below, so here we
        # only require every named selection to match (as with named_and_multi).
        sels = condition_meta.get("selections", [])
        selection_match = all(sel_results.get(s, False) for s in sels) if sels else False

    elif condition_type in (
        "named_selection_minus_filter",
        "named_selection_minus_filters",
    ):
        groups = condition_meta.get("groups", [])
        selection_match = sel_results.get(groups[0], False) if groups else False

    if not selection_match:
        return False

    if filter_results and any(filter_results.values()):
        return False

    return True


MITRE_TACTIC_NAMES = {
    "attack.execution": "Running malicious code",
    "attack.persistence": "Maintaining access after reboot",
    "attack.privilege-escalation": "Gaining higher permissions",
    "attack.privilege_escalation": "Gaining higher permissions",
    "attack.defense-evasion": "Hiding from security tools",
    "attack.defense_evasion": "Hiding from security tools",
    "attack.credential-access": "Stealing passwords or tokens",
    "attack.credential_access": "Stealing passwords or tokens",
    "attack.discovery": "Mapping the system or network",
    "attack.lateral-movement": "Spreading to other machines",
    "attack.lateral_movement": "Spreading to other machines",
    "attack.collection": "Gathering sensitive data",
    "attack.exfiltration": "Sending stolen data out",
    "attack.command-and-control": "Communicating with attacker infrastructure",
    "attack.command_and_control": "Communicating with attacker infrastructure",
    "attack.impact": "Damaging or destroying systems/data",
    "attack.initial-access": "First entry into a system",
    "attack.initial_access": "First entry into a system",
    "attack.reconnaissance": "Gathering info before an attack",
    "attack.resource-development": "Setting up attack infrastructure",
    "attack.resource_development": "Setting up attack infrastructure",
    "attack.stealth": "Avoiding detection",
    "attack.defense-impairment": "Disabling security controls",
    "attack.defense_impairment": "Disabling security controls",
}

LEVEL_EXPLANATIONS = {
    "critical": "This pattern is almost always malicious",
    "high": "This pattern is commonly used in real attacks",
    "medium": "This pattern is suspicious and warrants caution",
}


def format_alert(rule):
    """Format a matched rule into a beginner-friendly alert message."""
    title = rule.get("title", "Unknown Rule")
    level = rule.get("level", "unknown")
    description = rule.get("description", "")
    tags = rule.get("tags", [])
    references = rule.get("references", [])

    mitre_techniques = [
        t.replace("attack.", "").upper()
        for t in tags if t.startswith("attack.t")
    ]
    tactics = [
        MITRE_TACTIC_NAMES[t]
        for t in tags if t in MITRE_TACTIC_NAMES
    ]

    msg = f"SECURITY ALERT: {title}\n\n"
    msg += f"Severity: {level.upper()} - {LEVEL_EXPLANATIONS.get(level, '')}\n\n"

    msg += "WHY THIS IS SUSPICIOUS:\n"
    if description:
        desc_clean = description.strip().replace("\n", " ")
        msg += f"{desc_clean}\n"
    if tactics:
        msg += f"\nAttack category: {'; '.join(tactics)}\n"
        msg += "(This means an attacker could use this type of command to: "
        msg += tactics[0].lower() + ")\n"

    msg += "\nBEFORE YOU APPROVE:\n"
    msg += "- Do you recognize this command and understand what it does?\n"
    msg += "- Did you or a trusted tool intentionally request this?\n"
    msg += "- If unsure, deny it - you can always run it later after reviewing.\n"

    if mitre_techniques:
        msg += f"\nTechnical reference: MITRE ATT&CK {', '.join(mitre_techniques)}"
        if references:
            msg += f" | {references[0]}"
        msg += "\n"

    return msg


def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        json.dump({}, sys.stdout)
        return

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        json.dump({}, sys.stdout)
        return

    rules = load_rules()
    if not rules:
        json.dump({}, sys.stdout)
        return

    floor = _severity_floor_rank()
    if floor > 1:
        rules = [r for r in rules if _LEVEL_RANK.get(r.get("level", "low"), 0) >= floor]
        if not rules:
            json.dump({}, sys.stdout)
            return

    image = extract_image(command)

    matched_rules = []
    for rule in rules:
        if evaluate_rule(rule, command, image):
            matched_rules.append(rule)
            if len(matched_rules) >= 3:
                break

    if not matched_rules:
        json.dump({}, sys.stdout)
        return

    messages = [format_alert(r) for r in matched_rules]
    combined = "\n\n---\n\n".join(messages)

    first = matched_rules[0]
    response = clamp_and_emit(
        "sigma_engine",
        "ask",
        combined,
        pattern_matched=first.get("id") or first.get("title", "sigma_rule"),
        command=command,
    )
    json.dump(response if response else {}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
