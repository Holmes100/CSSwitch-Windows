"""Deterministic parsers for approved source-test framework output."""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence


_UNITTEST_LINE = re.compile(
    r"^([^ ()]+) \(([^()]+)\) \.\.\. ?(.*)$",
)
_UNITTEST_FAILURE = re.compile(
    r"^(FAIL|ERROR): (.+)$",
)
_UNITTEST_STATE = re.compile(r"^(ok|FAIL|ERROR|skipped .+)$")
_UNITTEST_RAN = re.compile(
    r"^Ran ([1-9][0-9]*) tests? in (?:0|[1-9][0-9]*)(?:\.[0-9]+)?s$",
)
_UNITTEST_OK = re.compile(r"^OK(?: \(skipped=([1-9][0-9]*)\))?$")
_UNITTEST_FAILED = re.compile(r"^FAILED \(([^()]*)\)$")
_UNITTEST_SEPARATOR = "-" * 70
_RUST_LINE = re.compile(
    r"^test (.+) \.\.\. (ok|FAILED|ignored(?:, .+)?)$",
)
_NODE_SUBTEST = re.compile(r"^\s*# Subtest: (.+)$")
_NODE_RESULT = re.compile(
    r"^\s*(ok|not ok) \d+ - (.+?)(?: # (SKIP|TODO)(?: .*)?)?\s*$",
)
_SHELL_RESULT = re.compile(
    r"^SOURCE_GATE_COMPONENT ([^ ]+) (PASS|FAIL|SKIP|TODO|NOT_RUN)$",
)


def _states() -> dict[str, list[str]]:
    return {
        "passed": [], "failed": [], "skipped": [], "ignored": [],
        "todo": [], "not_run": [],
    }


def _match_expected(
    reported: str,
    expected: Sequence[str],
    *,
    separator: str,
) -> str | None:
    matches = [
        item for item in expected
        if item == reported or item.endswith(separator + reported)
    ]
    return matches[0] if len(matches) == 1 else None


def _unittest(text: str, expected: Sequence[str]):
    lines = text.splitlines()
    discovered: list[str] = []
    state_by_id: dict[str, str] = {}
    states = _states()
    malformed = False
    pending: str | None = None
    provisional: set[str] = set()
    failure_events = {"FAIL": 0, "ERROR": 0}
    failure_event_ids: set[str] = set()
    labels: dict[str, str] = {}
    for test_id in expected:
        test_class, separator, method = test_id.rpartition(".")
        label = method + " (" + test_class + ")"
        if not separator or label in labels:
            malformed = True
        labels[label] = test_id

    def classify(test_id: str, state: str) -> None:
        nonlocal malformed
        category = (
            "passed" if state == "ok"
            else "skipped" if state.startswith("skipped ")
            else "failed"
        )
        if test_id in state_by_id:
            if state_by_id[test_id] != category:
                malformed = True
            return
        state_by_id[test_id] = category

    def discover(test_id: str) -> None:
        nonlocal malformed
        if test_id in discovered:
            malformed = True
        else:
            discovered.append(test_id)
        if test_id not in expected:
            malformed = True

    def parse_prefixes(line: str) -> bool:
        nonlocal malformed, pending
        fragment = line
        consumed = False
        while True:
            match = _UNITTEST_LINE.match(fragment)
            if match is None:
                return consumed
            consumed = True
            method, test_class, tail = match.groups()
            test_id = test_class + "." + method
            if pending is not None:
                provisional.add(pending)
                pending = None
            discover(test_id)
            state_match = _UNITTEST_STATE.fullmatch(tail)
            if state_match:
                classify(test_id, state_match.group(1))
                pending = None
                return True
            if _UNITTEST_LINE.match(tail) is not None:
                provisional.add(test_id)
                fragment = tail
                continue
            pending = test_id
            return True

    for line in lines:
        if parse_prefixes(line):
            continue
        state_match = _UNITTEST_STATE.fullmatch(line)
        if state_match:
            if pending is None:
                malformed = True
            else:
                classify(pending, state_match.group(1))
                pending = None
            continue
        failure_match = _UNITTEST_FAILURE.match(line)
        if failure_match:
            state, reported = failure_match.groups()
            matched = [
                (label, test_id)
                for label, test_id in labels.items()
                if reported == label
                or (
                    reported.startswith(label + " (")
                    and reported.endswith(")")
                )
            ]
            if len(matched) != 1:
                malformed = True
                continue
            _label, test_id = matched[0]
            if test_id not in discovered:
                discovered.append(test_id)
            classify(test_id, state)
            failure_events[state] += 1
            failure_event_ids.add(test_id)
            if pending == test_id:
                pending = None
            provisional.discard(test_id)

    executed = list(state_by_id)
    for test_id, state in state_by_id.items():
        if state == "passed":
            states["passed"].append(test_id)
        elif state == "skipped":
            states["skipped"].append(test_id)
        else:
            states["failed"].append(test_id)

    # A verbose per-test token is not completion authority: a descendant that
    # inherits stdout/stderr can print one. Bind the unique terminal unittest
    # footer, require it at the nonempty tail, and reconcile its counts with
    # the parsed per-test states.
    nonempty = [line for line in lines if line]
    ran = [
        (index, match)
        for index, line in enumerate(nonempty)
        if (match := _UNITTEST_RAN.match(line))
    ]
    terminals = []
    for index, line in enumerate(nonempty):
        ok = _UNITTEST_OK.match(line)
        failed = _UNITTEST_FAILED.match(line)
        if ok is not None or failed is not None:
            terminals.append((index, ok, failed))
    if (
        pending is not None
        or provisional
        or failure_event_ids != set(states["failed"])
        or len(ran) != 1
        or len(terminals) != 1
        or len(nonempty) < 3
        or nonempty[-3] != _UNITTEST_SEPARATOR
        or ran[0][0] != len(nonempty) - 2
        or terminals[0][0] != len(nonempty) - 1
        or int(ran[0][1].group(1)) != len(expected)
    ):
        malformed = True
    elif terminals[0][1] is not None:
        skipped = int(terminals[0][1].group(1) or "0")
        if (
            states["failed"]
            or any(failure_events.values())
            or skipped != len(states["skipped"])
        ):
            malformed = True
    else:
        summary: dict[str, int] = {}
        raw_fields = terminals[0][2].group(1).split(", ")
        for field in raw_fields:
            name, separator, raw_count = field.partition("=")
            if (
                separator != "="
                or name not in {"failures", "errors", "skipped"}
                or name in summary
                or not re.fullmatch(r"[1-9][0-9]*", raw_count)
            ):
                malformed = True
                continue
            summary[name] = int(raw_count)
        if (
            summary.get("failures", 0) != failure_events["FAIL"]
            or summary.get("errors", 0) != failure_events["ERROR"]
            or summary.get("skipped", 0) != len(states["skipped"])
            or not states["failed"]
        ):
            malformed = True
    return discovered, executed, states, malformed


def _rust(
    text: str,
    expected: Sequence[str],
    approved_ignored_reasons: Mapping[str, str],
):
    discovered: list[str] = []
    executed: list[str] = []
    states = _states()
    malformed = False
    for line in text.splitlines():
        match = _RUST_LINE.match(line)
        if not match:
            continue
        reported, state = match.groups()
        matched = _match_expected(reported, expected, separator="::")
        test_id = matched if matched is not None else reported
        if test_id in discovered:
            malformed = True
            continue
        discovered.append(test_id)
        executed.append(test_id)
        if matched is None:
            malformed = True
        category = (
            "ignored" if state.startswith("ignored")
            else {"ok": "passed", "FAILED": "failed"}[state]
        )
        if category == "ignored":
            marker = "ignored, "
            reason = state[len(marker):] if state.startswith(marker) else None
            if (
                matched is None
                or reason is None
                or approved_ignored_reasons.get(test_id) != reason
            ):
                malformed = True
        states[category].append(test_id)
    return discovered, executed, states, malformed


def _node(text: str, expected: Sequence[str]):
    subtests = [
        match.group(1)
        for line in text.splitlines()
        if (match := _NODE_SUBTEST.match(line))
    ]
    result_states: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = _NODE_RESULT.match(line)
        if not match:
            continue
        status, name, directive = match.groups()
        result_states.setdefault(name, []).append(
            "skipped" if directive == "SKIP"
            else "todo" if directive == "TODO"
            else "passed" if status == "ok"
            else "failed"
        )
    discovered: list[str] = []
    executed: list[str] = []
    states = _states()
    malformed = False
    for name in subtests:
        matched = _match_expected(name, expected, separator="::")
        test_id = matched if matched is not None else name
        if test_id in discovered:
            malformed = True
            continue
        discovered.append(test_id)
        candidates = result_states.get(name, [])
        if matched is None:
            malformed = True
        if len(candidates) != 1:
            malformed = True
            continue
        executed.append(test_id)
        states[candidates[0]].append(test_id)
    return discovered, executed, states, malformed


def _shell(text: str, expected: Sequence[str]):
    discovered: list[str] = []
    executed: list[str] = []
    states = _states()
    malformed = False
    table = {
        "PASS": "passed", "FAIL": "failed", "SKIP": "skipped",
        "TODO": "todo",
    }
    for line in text.splitlines():
        match = _SHELL_RESULT.match(line)
        if not match:
            continue
        reported, state = match.groups()
        matched = _match_expected(reported, expected, separator=":")
        test_id = matched if matched is not None else reported
        if test_id in discovered:
            malformed = True
            continue
        discovered.append(test_id)
        if matched is None:
            malformed = True
        if state == "NOT_RUN":
            states["not_run"].append(test_id)
            continue
        executed.append(test_id)
        states[table[state]].append(test_id)
    return discovered, executed, states, malformed


def parse_framework(
    kind: str,
    text: str,
    expected: Sequence[str],
    approved_ignored_reasons: Mapping[str, str] | None = None,
) -> tuple[list[str], list[str], dict[str, list[str]], bool]:
    if kind in {"python", "inventory"}:
        return _unittest(text, expected)
    if kind == "rust":
        return _rust(text, expected, approved_ignored_reasons or {})
    if kind == "frontend":
        return _node(text, expected)
    if kind == "shell":
        return _shell(text, expected)
    raise ValueError("unsupported parser kind")
