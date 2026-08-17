# Intentionally-vulnerable fixture used by mytool's own test suite.
# Every value below is fake/demo data - no real credentials or systems.

import os
import pickle
import requests
import ssl
import subprocess

os.system("ls -la")

proc = subprocess.run("ls -la", shell=True)

output = subprocess.getoutput("hostname")

payload = pickle.loads(open("data.pkl", "rb").read())
data = pickle.load(open("data.pkl", "rb"))

resp = requests.get("https://example.com/api", verify=False)

ctx = ssl.create_default_context()
ctx.check_hostname = False

user_input = "1 OR 1=1"
cursor.execute("SELECT * FROM users WHERE id = " + user_input)

name = "admin"
db.execute("INSERT INTO roles (name) VALUES ('{}')".format(name))