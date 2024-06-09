# VulnInsights

**Crack the code!** Unveil vulnerabilities, exploits, and defenses with VulnInsights. Dive into secure coding practices, Active Directory security, and network penetration testing.

## Table of Contents

- [Overview](#overview)
- [WebApp Hacking](#web-application-vulnerabilities)
- [Secure Coding](#secure-coding)
- [Active Directory](#active-directory)
- [Reporting Templates](#reporting-templates)
- [Contributing](#contributing)
- [License](#license)
- [Questions?](#questions)

## Overview

VulnInsights provides a comprehensive reference for understanding and addressing various vulnerabilities in secure coding practices.

## Web Application Vulnerabilities

Explore various vulnerabilities commonly found in web applications:

- [**Open Redirect**](web-app-vulnerabilities/open-redirect.md)
  - Learn about the risks associated with open redirects and how to prevent them.
  
- [**Cross-Site Scripting (XSS)**](web-app-vulnerabilities/xss.md)
  - Understand XSS vulnerabilities and techniques to mitigate them.
  
- [**SQL Injection (SQLi)**](web-app-vulnerabilities/sqli.md)
  - Discover the dangers of SQL injection attacks and how to secure your application against them.
  
- [**Server-Side Template Injection (SSTI)**](web-app-vulnerabilities/ssti.md)
  - Explore the risks of SSTI vulnerabilities and best practices for protection.
  
- [**Server-Side Request Forgery (SSRF)**](web-app-vulnerabilities/ssrf.md)
  - Learn about SSRF attacks and strategies to defend against them.
  
- [**Cross-Site Request Forgery (CSRF)**](web-app-vulnerabilities/csrf.md)
  - Understand CSRF vulnerabilities and measures to prevent them.

## Secure Coding

### CWE-22

- [**Insecure Deserialization using `JsonConvert.DeserializeObject` (.NET)**](secure-coding/docs/CWE-22/dotnet/JsonConvert-Deserialisation.md)
- [**Path Traversal in Metasphere (Java)**](secure-coding/docs/CWE-22/java/path-traversal-metasphere.md)
- [**Path Traversal in BigBlueButton (Groovy)**](secure-coding/docs/CWE-22/groovy/bigbluebutton-lfi.md)

### CWE-89

- [**SQL Injection Vulnerability due to Insecure Processing of Authorization Header in anything-llm (JavaScript)**](secure-coding/docs/CWE-89/javascript/anything-llm-sql-injection-vulnerabilities.md)

### CWE-23

- [**Improper Input Validation Leads to Arbitrary File Deletion in anything-llm (Python)**](secure-coding/docs/CWE-23/python/anything-llm-arbitrary-file-deletion.md)

### CWE-98

- [**Restricted LFI in Suite-CRM (PHP)**](secure-coding/docs/CWE-98/php/suite-crm-unsanitized-inclusion.md)

### CWE-338

- [**Use of Weak PRNG in Alova (Java)**](secure-coding/docs/CWE-338/java/alovoa-insecure-random.md)

## Active Directory

- [Overview](active-directory/overview.md)
- [Attack Vectors](active-directory/attack-vectors.md)
- [Defense Strategies](active-directory/defense-strategies.md)

## Reporting Templates

- [Open Redirect Vulnerability](reporting-templates/open-redirect.md)

## Contributing

We welcome contributions and insights. Check [Contributing Guidelines](contributing.md) for details.

## License

This project is under the [MIT License](LICENSE).

## Questions?

Feel free to [open an issue](https://github.com/D4mianWayne/VulnInsights/issues). Thanks for your input!
