# Clean fixture: safe patterns that must produce zero SAST findings.

import os
import ssl
import subprocess
import requests

proc = subprocess.run(["ls", "-la"], shell=False)

if os.path.isdir("/tmp"):
    print("tmp exists")

resp = requests.get("https://example.com/api", verify=True)

ctx = ssl.create_default_context()
ctx.check_hostname = True

user_input = "1 OR 1=1"
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))