# Ground-truth secret fixtures for benchmarking. Each real secret below is
# deliberately fake/rotated and matches one of mytool's secret rules. The
# golden file records the expected (file, line) for each.

import os

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_abcDEF0123456789ghiJKLmnopqrstuVWXYZ"
GITLAB_TOKEN = "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
STRIPE_LIVE_KEY = "sk_live_51HXaXfLk2YqVz0tGHCqMp3R4sT5uV6wX7yZ8Ab9Cd0EfG"
STRIPE_RESTRICTED = "rk_live_51HXaXfLk2YqVz0tGHCqMp3R4sT5uV6wX7yZ8"
STRIPE_TEST_KEY = "sk_test_51HXaXfLk2YqVz0tGHCqMp3R4sT5uV6wX7yZ8Ab9Cd0EfG"
GOOGLE_API_KEY = "AIzaSyD09tYbXcVw2fGzQvNkLmRpQT7jUdHx8aBCdE"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
TWILIO_API_KEY = "SK0123456789abcdef0123456789abcdef"
SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
OPENAI_API_KEY = "sk-proj-3NlbfQtC7r2WpJoMWY4n8UQdXkT1Zv5cA6eH9dRiM2"
NPM_TOKEN = "npm_1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p"
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmcCJDZkM2E4Mzc2LTRkNzUtNDM0OC1hMTU2LTVkYWFmZDlkODcyZg"
SHOPIFY_TOKEN = "shpat_0123456789abcdef0123456789abcdef"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"
TELEGRAM_BOT = "9876543210:AAHqkPqk8XoD1aB2c3d4e5f6g7h8i9j0kLmNopQs"
HUGGINGFACE_TOKEN = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"
AZURE_STORAGE_KEY = "q8fR3nT7vX2mK5pS9zW1bC4eD6gH8jL0kN2mP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3jK5lM7nP0"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"

# --- Non-secret decoys: must NOT be flagged (false-positive traps). ---
AWS_PLACEHOLDER = "AKIA-REPLACE-WITH-YOUR-OWN"  # invalid charset, not a real key
GITHUB_PLACEHOLDER = "ghp_PLACEHOLDER_NOTHEREAL"
DUMMY_TOKEN = "your_token_here"
EXAMPLE_SECRET = "example_secret"  # real-looking but a documented placeholder
SAMPLE_TOKEN = "changeme"
DOC_API_KEY = "your_api_key_here"
ENTROPY_VALUE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # low entropy, repeated char

# Generic keyword assignment that IS a real (fake) secret.
API_SECRET = "api_key='f8vQm3sL2xNw7kP9tR4uY6cZ'"
CLIENT_SECRET = "client_secret='Gh7Pd2Jq4Xr8Mn5Bt3Vw6Kz9Lc1'"
ACCESS_TOKEN = "access_token='E9tG4Hr7Km2Pn5Qs8Yw1Zx3Vb6'"


def connect():
    return AWS_SECRET_ACCESS_KEY
