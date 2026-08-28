# Ground-truth SAST fixtures for benchmarking against bandit/semgrep.
# Expected findings are recorded in bench/goldens/code.json.

import os
import pickle
import sqlite3
import ssl
import subprocess

# --- True positives ---


def eval_user(input_data):
    # CWE-95 arbitrary code execution
    return eval(input_data)


def exec_user(code):
    exec(code)


def run_shell(cmd):
    # CWE-78 shell injection
    return subprocess.run(cmd, shell=True)


def old_style(cmd):
    return os.system(cmd)


def make_request(url):
    # CWE-295 TLS verification disabled
    import requests
    return requests.get(url, verify=False)


def connect_ssl():
    # CWE-295 hostname verification disabled
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_NONE
    ctx.check_hostname = False
    return ctx


def load_data(path):
    # CWE-502 unsafe deserialization
    with open(path, "rb") as fh:
        return pickle.load(fh)


def query_user(user_id):
    # CWE-89 SQL injection via string interpolation
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return cur.fetchall()


def query_user_fmt(user_id):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cur.fetchall()


def query_safe(user_id):
    # Safe parameterized query - must NOT be flagged.
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()


def run_clean():
    # Adding two numbers - safe, must NOT be flagged.
    return 2 + 2


def normal_subprocess():
    # No shell=True - safe, must NOT be flagged.
    return subprocess.run(["ls", "-l"], capture_output=True)
