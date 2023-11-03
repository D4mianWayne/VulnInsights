# Vulnerability Reference Guide

## Common Weakness Enumeration (CWEs)

- **CWE-23: Insecure Deserialization**
  - [CWE-23 Details](https://cwe.mitre.org/data/definitions/23.html)

- **CWE-89: SQL Injection**
  - [CWE-89 Details](https://cwe.mitre.org/data/definitions/89.html)

- **CWE-22: Improper Input Validation**
  - [CWE-22 Details](https://cwe.mitre.org/data/definitions/22.html)

## Vulnerabilities by Language

- **.NET**
  - **Insecure Deserialization using `JsonConvert.DeserializeObject`**
    - [Vulnerability Analysis](.NET/Deserialization)
    - **CWE Reference**: [CWE-23](https://cwe.mitre.org/data/definitions/23.html)

- **JavaScript**
  - **SQL Injection Vulnerability due to Insecure Processing of Authorization Header**
    - [Vulnerability Details](JavaScript/anything-llm-vulnerabilities.md)
    - **CWE Reference**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

- **Python**
  - **Improper Input Validation Leads to Arbitrary File Deletion**
    - [Vulnerability Report](Python/anything-llm.md)
    - **CWE Reference**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
