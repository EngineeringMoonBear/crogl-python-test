# GitHub Advisories Fetch & Catagorize

This script uses GitHub's GraphQL API to download all reviewed security advisories related to Python packages (`pip` ecosystem), organize them by severity, and save them as CSV files.

## 🔧 Features

- Uses GitHub GraphQL API
- Downloads all `pip` ecosystem advisories
- Organizes advisories into folders: `low`, `moderate`, `high`, `critical`
- Outputs a `.csv` for each severity category
- Compresses the output into a zip file

## 📦 Requirements

- Python 3.7+
- GitHub Personal Access Token (PAT) with public repo access

Install required packages:
pip install requests pandas

What is Pandas?
Pandas is a Python library for data manipulation and analysis. It's designed to make working with structured data fast, easy, and expressive.