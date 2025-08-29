# **CISA CVE Vulnrichment CI/CD Pipeline**
## _Overview_
This repository contains an end-to-end, fully automated CI/CD pipeline and Python tooling to collect, enrich, and publish a comprehensive CVE dataset to Kaggle for public use that leverages [https://github.com/cisagov/vulnrichment](_CISA's official vulnrichment repository_).

The result: an up-to-date, business-ready dataset suitable for analytics, reporting, threat modeling, and risk management—published daily to Kaggle.
Find the dataset here: _https://www.kaggle.com/datasets/junaidmohammad9248/cisa-cve-vulnrichment_


## _Why did I create this repository?_
While working on a project for a business intelligence I wanted to use a cybersecurity dataset and analyze common vendors/products that were most susceptible to be being exploited so that I can create a comprehensive report of their CVE records, vulnerability ratings etc. However, I found that existing CVE datasets to be either not descriptive enough or lacking coverage of recent CVSS/SSVC and CWE data. Combining multiple sources was cumbersome and error-prone. This project solves that by:

1. Using authoritative source data from CISA.
2. Enriching each CVE with business-context fields: CVSS, SSVC, CWE, affected products/vendors, exploit status, and more.
3. Automating end-to-end extraction, transformation, and publication via modern CI/CD best practices.

## _Features of pipeline_
### Python Extraction Scripts
Two scripts, one dedicated to extraction of cve records from vulnrichment repository and creating a csv dataset for each available year, the second to automate uploading to Kaggle using Kaggle CLI commands

### GitHub Actions CI/CD Pipeline
