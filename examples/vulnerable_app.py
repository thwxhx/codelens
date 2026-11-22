"""Intentionally bad code: a demo target for `codelens review examples/`.

Do not copy anything from this file. Every line is a bug on purpose.
"""

import hashlib
import os
import pickle
import subprocess
import sqlite3

import requests
import yaml

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "k8Jd92Lq0Pz7XcVb3NmR"


def load_user(db, user_id, cache={}):
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    if user_id in cache:
        return cache[user_id]
    return cur.fetchone()


def run_report(name, fmt):
    os.system("generate-report " + name)
    subprocess.run(f"convert {name} {fmt}", shell=True)
    return eval(fmt)


def restore(blob, config_text):
    data = pickle.loads(blob)
    config = yaml.load(config_text)
    try:
        requests.get("https://api.internal/sync", verify=False)
    except:
        pass
    return data, config, hashlib.md5(blob).hexdigest()


def classify(a, b, c, d, e, f, g):
    # TODO: this is a mess
    if a == None:
        return 0
    if a:
        if b:
            for x in c:
                if x:
                    while d:
                        if e and f or g:
                            return 1
    return 2
