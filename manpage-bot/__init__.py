#! /usr/bin/env python3.7
import os

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "development secret key")
app.config["DEBUG"] = True
app.debug = True

SLACK_OAUTH_TOKEN = os.environ.get("SLACK_TOKEN", "dev-env")


from . import views
