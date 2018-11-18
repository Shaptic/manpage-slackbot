#! /usr/bin/env python3.7
""" Contains the tokens used by the various workspaces that integrate this bot.
"""
import os

TOKENS = {
    "T4MMX6NBC": os.environ.get("DEEPCHAT_SLACK_TOKEN", "dev-env-dc"),
    "T6J1VEXME": os.environ.get("GIOS_SLACK_TOKEN", "dev-env-gios"),
    "default": os.environ.get("GIOS_SLACK_TOKEN", "dev-env-gios"),
}

def get_token(event_js):
    return TOKENS.get(event_js.get("team_id", ""), TOKENS["default"])
