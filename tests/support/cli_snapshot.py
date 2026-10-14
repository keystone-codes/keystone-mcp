"""Collect frozen CLI flag rows from the keystone-mcp argparse tree."""

from __future__ import annotations

import argparse


def _subparsers_actions(parser: argparse.ArgumentParser) -> list[argparse._SubParsersAction]:
    return [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)]


def _flag_value_kind(action: argparse.Action) -> str:
    if action.nargs == 0 or isinstance(action, argparse._StoreTrueAction):
        return "no"
    if isinstance(action, argparse._StoreFalseAction):
        return "no"
    if action.choices is not None:
        return "yes"
    if action.type is not None and action.type is not bool:
        return "yes"
    return "no"


def _primary_option(action: argparse.Action) -> str | None:
    options = [opt for opt in action.option_strings if opt not in ("-h", "--help")]
    if not options:
        return None
    return max(options, key=len)


def collect_cli_flags(parser: argparse.ArgumentParser, prefix: tuple[str, ...]) -> dict[str, str]:
    rows: dict[str, str] = {}
    subparser_actions = _subparsers_actions(parser)
    if subparser_actions:
        for action in subparser_actions:
            for name in sorted(action.choices):
                sub = action.choices[name]
                rows.update(collect_cli_flags(sub, prefix + (name,)))
        return rows

    command = " ".join(prefix)
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        if action.option_strings:
            option = _primary_option(action)
            if option is None:
                continue
            key = f"{command} {option}".strip()
            rows[key] = " ".join(
                (
                    f"required={'yes' if action.required else 'no'}",
                    f"value={_flag_value_kind(action)}",
                )
            )
            continue
        if action.dest in {"help"}:
            continue
        metavar = action.metavar or action.dest
        if isinstance(metavar, tuple):
            metavar = metavar[0]
        key = f"{command} <{metavar}>".strip()
        rows[key] = f"required={'yes' if action.required else 'no'} value=yes"
    return rows
