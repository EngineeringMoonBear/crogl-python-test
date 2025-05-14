import requests
import pandas as pd
import os
import zipfile
from pathlib import Path

#Github GraphQL API endpoint
GITHUB_API_URL = "https://api.github.com/graphql"
#GITHUB_TOKEN = ""

# GraphQL query to fetch pip advisories
QUERY = """
query ($cursor: String) {
  securityAdvisories(first: 100, after: $cursor, ecosystem: PIP, orderBy: {field: UPDATED_AT, direction: DESC}) {
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
        data = response.json()
        advisories_batch = data['data']['securityAdvisories']['nodes']
        advisories.extend(advisories_batch)

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
            cve_id = next((i["value"] for i in a["identifiers"] if i["type"] == "CVE"), "")
            pkg = a['vulnerabilities']['nodes'][0]['package']['name'] if a['vulnerabilities']['nodes'] else ""
            version_range = a['vulnerabilities']['nodes'][0]['vulnerableVersionRange'] if a['vulnerabilities']['nodes'] else ""
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
                "References": ", ".join(r['url'] for r in a['references'])
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
    advisories = fetch_advisories()
    print(f"Fetched {len(advisories)} advisories.")
    print("Organizing and exporting...")
    organize_and_export(advisories)
    print("Done. Files saved in 'advisories/' directory.")