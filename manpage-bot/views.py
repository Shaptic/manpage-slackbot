#! /usr/bin/env python3.7
import re
import json
import time
import functools
from   pprint import pprint

from   flask import request, jsonify
import requests as curl

from . import app
from .tokens import get_token
from .links  import ERRNO_STRINGS, MANPAGE_MAPPING


COMMAND_PATTERN = r"\bman ([-\w]+)"
COMMAND_REGEX = re.compile(COMMAND_PATTERN, re.IGNORECASE)
SEEN_EVENTS = []


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

    # The main command contains the pattern:
    #       man [function name]
    #
    # The function name is one word, potentially with underscores or hypens.
    # Where the actual mention of the bot occurs is irrelevant.
    matches = re.search(COMMAND_REGEX, event["text"])

    # We ALSO support direct mentions with *only* the [function name], as in:
    #       @man [function name]
    #
    # but to support this we need to build the regex based on our own Slack user
    # identifier, which is in "authed_users". So:
    if matches is None:
        user_id = js["authed_users"][0]
        alt_regex = re.compile("^<@%s> ([-\\w]+)\s*$" % user_id, re.IGNORECASE)
        matches = re.search(alt_regex, event["text"])

    # Respond with a message linking to the requested man page, if it exists. If
    # it doesn't, indicate that!
    #
    # https://slack.com/api/chat.postMessage
    if matches is None:
        message = "Invalid query; use the form `man [function]` :nerd_face:"
    else:
        query = matches.groups()[0]

        message = f"No `man` page found for: {query}."
        if query in MANPAGE_MAPPING:
            url = MANPAGE_MAPPING[query]

            # Check the requests we've served so we don't re-query... Kind of a
            # hack... necessary to not be spammy when Heroku "fresh start"s us.
            #
            # I'm way too lazy to make this thread-safe lol.
            global SEEN_EVENTS
            if js["event_id"] in SEEN_EVENTS:
                return {"message": "We've already responded to this..."}, 304
            else:
                SEEN_EVENTS.append(js["event_id"])
                SEEN_EVENTS = SEEN_EVENTS[-10:]

            result = curl.get(url[0])
            if result.status_code == curl.codes.ok:
                if len(url) > 1:
                    message = f"I found {len(url)} results for `{query}`:\n  "
                    message += '\n  '.join(url)
                else:
                    message = f"`{query}`: {url[0]}"

                # append = ""
                # for anchor, matches in {
                #     "#RETURN_VALUE": ("return value", " rv ", "returns"),
                #     "#ERRORS": ERRNO_STRINGS + ["error", "errno"],
                #     "#NOTES": ("notes", )
                # }.items():
                #     if any(map(lambda m: event["text"].lower().find(m) != -1, matches)):
                #         append = anchor
                #         break

                # message += append

        curl.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": "Bearer " + get_token(js),
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
