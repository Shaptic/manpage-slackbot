#! /usr/bin/env python3.7
import os

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "development secret key")
app.config["DEBUG"] = True
app.debug = True

from . import views
