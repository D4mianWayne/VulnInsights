# Vulnerability Reference Guide

Welcome to the Vulnerability Reference Guide repository! This guide provides concise analyses of vulnerabilities categorized based on Common Weakness Enumerations (CWEs).

## CWEs

- **CWE-23: Insecure Deserialization**
  - [Details](https://cwe.mitre.org/data/definitions/23.html)

- **CWE-89: SQL Injection**
  - [Details](https://cwe.mitre.org/data/definitions/89.html)

- **CWE-22: Improper Input Validation**
  - [Details](https://cwe.mitre.org/data/definitions/22.html)

## Vulnerabilities

### CWE-22

- **Insecure Deserialization using `JsonConvert.DeserializeObject`**
  - [Analysis](docs/CWE-22/dotnet/JsonConvert-Deserialisation.md)
  - DotNet

### CWE-89

- **SQL Injection Vulnerability due to Insecure Processing of Authorization Header**
  - [Analysis](docs/CWE-89/javascript/anything-llm-sql-injection-vulnerabilities.md)
  - JavaScript

### CWE-23

- **Improper Input Validation Leads to Arbitrary File Deletion**
  - [Analysis](docs/CWE-23/python/anything-llm-arbitrary-file-deletion.md)
  - Python

### CWE-98

- **Restricted LFI**
  - [Analysis](docs/CWE-98/php/suite-crm-unsanitized-inclusion.md)
  - PHP

## Contributing

We welcome contributions and insights. Check [Contributing Guidelines](contributing.md) for details.

## License

This project is under the [MIT License](LICENSE).

## Questions?

Feel free to [open an issue](https://github.com/your-username/VulnInsights/issues). Thanks for your input!
