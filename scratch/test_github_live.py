import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import httpx

load_dotenv()

token = os.getenv("GITHUB_API_TOKEN")
headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "ORACLE-Investigation-Engine/3.9",
    "Authorization": f"Bearer {token}"
}
client = httpx.Client(timeout=10.0, headers=headers)
r = client.get("https://api.github.com/user")
print("=" * 60)
print("REAL LIVE GITHUB USER & REPOSITORIES:")
print("=" * 60)
print("User status:", r.status_code)
if r.status_code == 200:
    u = r.json()
    print("GitHub Login:", u.get("login"))
    print("Name:        ", u.get("name"))
    print("Email:       ", u.get("email"))
    print("Public Repos:", u.get("public_repos"))

r_repos = client.get("https://api.github.com/user/repos?per_page=10&sort=updated")
print("\nRepositories status:", r_repos.status_code)
if r_repos.status_code == 200:
    for repo in r_repos.json():
        full_name = repo.get("full_name")
        branch = repo.get("default_branch")
        private = "Private" if repo.get("private") else "Public"
        print(f" -> {full_name} ({branch}, {private})")
