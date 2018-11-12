#! /usr/bin/env python3.7
import re
import json
import functools
from   pprint import pprint

from flask import request, jsonify

from . import app


def get_js(**kwargs):
    js = request.get_json(**kwargs)
    if js is None: return False
    if not isinstance(js, dict):
        js = json.loads(js)     # wtf tbh?
    return js

def json_endpoint(view_fn):
    """ Dumps the return value of a view function to JSON.
    """
    @functools.wraps(view_fn)
    def wrapper(*args, **kwargs):
        rv = view_fn(*args, **kwargs)
        if not isinstance(rv, tuple):
            errno = 200
        else:
            assert len(rv) == 2, "Invalid request return format."
            rv, errno = rv

        if errno < 200 or errno > 299:
            if isinstance(rv, str):
                rv = { "error": rv }
            elif "error" not in rv:
                rv["error"] = "An error occurred."

        rv["code"] = errno
        return jsonify(rv), errno

    return wrapper

@app.route("/", methods=["GET"])
def index():
    """ Displays a generic message.
    """
    return "Hey, you're not a Slack event...", 200

@app.route("/api/v1/action", methods=["POST"])
@json_endpoint
def process_event():
    """ Responds to a Slack events.
    """
    js = get_js()
    pprint(js)

    if js is False or "type" not in js:
        return {"message": "Request doesn't appear to be a Slack event!"}, 200

    return handlers.get(js["type"], on_event_failure)(js)

def on_challenge(js):
    """ Responds with the 'challenge' parameter.

    https://api.slack.com/events/url_verification
    """
    return { "challenge": js["challenge"] }, 200

def on_app_mention(js):
    """ Processes an `app_mention` event from Slack.

        {
            "type": "app_mention",
            "user": "U061F7AUR",
            "text": "<@U0LAN0Z89> is it everything a river should be?",
            "ts": "1515449522.000016",
            "channel": "C0LAN2Q65",
            "event_ts": "1515449522000016"
        }
    """
    return on_event_failure(js)

def on_event_failure(js):
    return {"message": "NotImplemented"}, 200


handlers = {
    "url_verification": on_challenge,
    "app_mention": on_app_mention,
}
