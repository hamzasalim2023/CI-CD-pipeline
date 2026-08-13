# Clean fixture - must produce zero findings.
# All values below are deliberate placeholders.

API_BASE = "https://api.example.com/v1"


def fetch_user(uid):
    return API_BASE + "/users/" + str(uid)


ACCESS_TOKEN = "your_token_here"
DB_PASSWORD = "example_secret"
AUTH_HEADER = {"Authorization": "Bearer " + "not-a-real-secret"}
CURRENT_USER = "hamzasalim2023"


def double(x):
    return x * 2