import os
import requests
import pandas as pd
import zipfile
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Read GitHub token from environment
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN not found in .env file or environment")

# GitHub GraphQL API endpoint
GITHUB_API_URL = "https://api.github.com/graphql"

# GraphQL query to fetch pip advisories
QUERY = """
query ($cursor: String) {
  securityAdvisories(first: 100, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
    pageInfo {
      endCursor
      hasNextPage
    }
    nodes {
      ghsaId
      summary
      description
      severity
      updatedAt
      publishedAt
      withdrawnAt
      references {
        url
      }
      identifiers {
        type
        value
      }
      vulnerabilities(first: 1) {
        nodes {
          package {
            name
            ecosystem
          }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Content-Type": "application/json"
}


def fetch_advisories():
    advisories = []
    cursor = None

    while True:
        response = requests.post(
            GITHUB_API_URL,
            json={"query": QUERY, "variables": {"cursor": cursor}},
            headers=HEADERS
        )

        if response.status_code != 200:
            raise Exception(f"GitHub API request failed: {response.status_code} - {response.text}")

        data = response.json()
        if 'errors' in data:
            raise Exception(f"GraphQL errors returned: {data['errors']}")

        advisories_batch = data['data']['securityAdvisories']['nodes']

        # Filter for only PIP ecosystem advisories
        pip_advisories = [
            a for a in advisories_batch
            if a['vulnerabilities']['nodes'] and
               a['vulnerabilities']['nodes'][0]['package']['ecosystem'] == "PIP"
        ]

        advisories.extend(pip_advisories)

        print(f"Fetched {len(pip_advisories)} pip advisories... (total so far: {len(advisories)})")

        page_info = data['data']['securityAdvisories']['pageInfo']
        if page_info['hasNextPage']:
            cursor = page_info['endCursor']
        else:
            break

    return advisories


def organize_and_export(advisories):
    base_path = Path("advisories")
    base_path.mkdir(exist_ok=True)

    severity_levels = ["LOW", "MODERATE", "HIGH", "CRITICAL"]
    csv_paths = []

    for severity in severity_levels:
        filtered = [a for a in advisories if a['severity'] == severity]
        if not filtered:
            continue

        rows = []
        for a in filtered:
            cve_id = next((i["value"] for i in a.get("identifiers", []) if i["type"] == "CVE"), "")
            pkg = a['vulnerabilities']['nodes'][0]['package']['name'] if a['vulnerabilities']['nodes'] else ""
            version_range = a['vulnerabilities']['nodes'][0]['vulnerableVersionRange'] if a['vulnerabilities']['nodes'] else ""
            references = ", ".join(r['url'] for r in a.get('references', []))

            rows.append({
                "GHSA ID": a['ghsaId'],
                "CVE ID": cve_id,
                "Package": pkg,
                "Version Range": version_range,
                "Severity": a['severity'],
                "Summary": a['summary'],
                "Published At": a['publishedAt'],
                "Updated At": a['updatedAt'],
                "Withdrawn At": a['withdrawnAt'],
                "References": references
            })

        df = pd.DataFrame(rows)
        severity_folder = base_path / severity.lower()
        severity_folder.mkdir(exist_ok=True)
        csv_path = severity_folder / f"{severity.lower()}_advisories.csv"
        df.to_csv(csv_path, index=False)
        csv_paths.append(csv_path)

    # Zip everything
    zip_path = base_path / "advisories_by_severity.zip"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        for path in csv_paths:
            zipf.write(path, arcname=str(path.relative_to(base_path)))


if __name__ == "__main__":
    print("Fetching advisories...")
    try:
        advisories = fetch_advisories()
        print(f"Fetched {len(advisories)} total advisories.")
    except Exception as e:
        print(f"Error fetching advisories: {e}")
        exit(1)

    print("Organizing and exporting...")
    try:
        organize_and_export(advisories)
        print("✅ Done. Files saved in 'advisories/' directory.")
    except Exception as e:
        print(f"Error writing files: {e}")
        exit(1)