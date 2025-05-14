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