#! /usr/bin/env python3.7
import re
import json
import functools

from flask import request

from . import app


def get_js(**kwargs):
    js = request.get_json(**kwargs)
    if js is None:
        raise TypeError("empty payload")
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

        if not isinstance(rv, str): rv = json.dumps(rv)
        return rv, errno

    return wrapper


@app.route("/api/v1/manpage", methods=["GET"])
@json_endpoint
def get_manpage():
    """ Responds to an `app_mention` event from Slack.

        {
            "type": "app_mention",
            "user": "U061F7AUR",
            "text": "<@U0LAN0Z89> is it everything a river should be?",
            "ts": "1515449522.000016",
            "channel": "C0LAN2Q65",
            "event_ts": "1515449522000016"
        }
    """
    js = get_js()
    print(js)
    return "{}"
