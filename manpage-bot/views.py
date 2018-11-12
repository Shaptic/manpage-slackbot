#! /usr/bin/env python3.7
import re
import json
import functools
from   pprint import pprint

from   flask import request, jsonify
import requests as curl

from . import app, SLACK_OAUTH_TOKEN


COMMAND_PATTERN = r"man (\w+)"
COMMAND_REGEX = re.compile(COMMAND_PATTERN, re.IGNORECASE)


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

@app.route("/api/v1/action", methods=["GET", "POST"])
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

    Full event structure for the "happy path," i.e. someone mentioning the bot
    directly in a channel that it already exists in.

        {
            "token": "ZZZZZZWSxiZZZ2yIvs3peJ",
            "team_id": "T061EG9R6",
            "api_app_id": "A0MDYCDME",
            "event": {
                "type": "app_mention",
                "user": "U061F7AUR",
                "text": "What is the hour of the pearl, <@U0LAN0Z89>?",
                "ts": "1515449522.000016",
                "channel": "C0LAN2Q65",
                "event_ts": "1515449522000016"
            },
            "type": "event_callback",
            "event_id": "Ev0LAN670R",
            "event_time": 1515449522000016,
            "authed_users": [
                "U0LAN0Z89"
            ]
        }
    """
    event = js["event"]

    # The only types of commands that are supported contain the pattern:
    #       man [function name]
    #
    # The function name is one word, potentially with underscores. Where the
    # actual mention of the bot occurs is irrelevant.
    matches = re.search(COMMAND_REGEX, event["text"])

    # Respond with a message linking to the requested man page, if it exists. If
    # it doesn't, indicate that!
    #
    # https://slack.com/api/chat.postMessage
    if matches is None:
        message = "No `man` page found for query."
    else:
        query = matches.groups()[0]
        url = f"http://man7.org/linux/man-pages/man2/{query}.2.html"
        message = f"`man {query}`: {url}"

        result = curl.get(url)
        pprint(url)
        pprint(result.status_code)
        if result.status_code != curl.codes.ok:
            message = f"No `man` page found for: {query}."

        curl.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": "Bearer " + SLACK_OAUTH_TOKEN,
                "Content-Type": "application/json",
            },
            json={
                "username": "Man Bot",
                "icon_emoji": ":computer:",
                "channel": event["channel"],
                "text": message,
                "unfurl_links": False,
            }
        )

    return {"message": message}, 200

def on_event(js):
    """ Extracts the inner event structure from a generic event.
    """
    event = js["event"]
    return handlers.get(event["type"], on_event_failure)(js)

def on_event_failure(js):
    return {"message": "NotImplemented"}, 200


handlers = {
    "event_callback": on_event,
    "url_verification": on_challenge,
    "app_mention": on_app_mention,
}
