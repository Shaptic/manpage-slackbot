import re
import urllib

# "It appears you have a bug"
# "Have you considered not doing that?"
# "Have you considered making it work correctly?""

# A bunch of regex for grabbing different phrases.
# https://media1.tenor.com/images/0ea3b27f9c436ee7a0c0550c3705ca6d/tenor.gif?itemid=4771310
TRIGGERS = {
    "IDK": [
        re.compile(r"i don'?t know", re.IGNORECASE),
        re.compile(r"idk", re.IGNORECASE),
    ],
    "BONNIE": {
        re.compile(r"weird bonnie error", re.IGNORECASE),
    },
}

RESPONSES = {
    "IDK": [
        "have you tried knowing?",
    ],
    "BONNIE": [
        "that"
    ],
}


def check_troll_potential(text):
    return None


# Actually useful stuff.
PIAZZA_REGEX = re.compile(r"\bpiazza\s+@(\d+)", re.IGNORECASE)
PIZZA_REGEX  = re.compile(r":pizza:\s+@(\d+)", re.IGNORECASE)
LMGTFY_REGEX = re.compile(r"^([\w\s\"'-']+)\?\s*$", re.IGNORECASE)

def check_piazza(matches):
    query = matches.groups()[0]
    message = f"https://piazza.com/class/jqkdjtajmtunj?cid={query} :pizza:"
    return message

def check_lmgtfy(matches):
    query = matches.groups()[0]

    # Respect politeness.
    url, icon = "lmgtfy.com/", ":troll_dance:"
    if "pls" in query or "please" in query:
        query = query.replace("please", "").replace("pls", "")
        url = "google.com/search"
        icon = ":smile_cat:"

    # Ignore empty queries lol thanks Tho
    query = query.strip()
    if not query: return ""

    arg = urllib.parse.urlencode({"q": query})
    message = f"https://{url}?{arg} {icon}"
    return message


TOOLS = [
    (PIAZZA_REGEX, check_piazza),
    (PIZZA_REGEX,  check_piazza),
    (LMGTFY_REGEX, check_lmgtfy),
]

def check_useful(text):
    for regex, handler in TOOLS:
        matches = re.search(regex, text)
        if matches is not None:
            return handler(matches)
