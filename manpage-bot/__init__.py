#! /usr/bin/env python3.7
import os

SLACK_OAUTH_TOKEN = os.environ.get("SLACK_TOKEN", "dev-env")

from flask import Flask
app = Flask(__name__)

from . import views
