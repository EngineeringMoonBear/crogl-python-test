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
