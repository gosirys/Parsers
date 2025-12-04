# Parsers

A collection of parsers and automation tools (mostly/all in Perl) developed for penetration testing and security assessment work between 2010 and 2023. These scripts were created to streamline common tasks during vulnerability assessments, infrastructure reconnaissance, password audits, phishing campaigns, and reporting workflows.

> **Note**: These tools are published primarily for archiving purposes and nostalgia. While some may still be useful and functional, they were written organically during actual engagements over many years and are not actively maintained. So, i don't recommend using them, you are better off looking for newer alternatives (plenty).

## Timeline

These tools span over a decade of security work:

- **2023**: HTTPx infrastructure parser for large-scale reconnaissance
- **2016**: Phishing campaign analytics and Nmap URL generators
- **2015**: LinkedIn employee email enumeration
- **2013**: Automated vulnerability research tool mining CVEDetails and SecurityFocus
- **2011**: Web crawler and Nmap to MindMap converter
- **2010 and earlier**: Email harvesting from search engines

Most scripts were written organically during actual engagements to solve specific problems and improve efficiency.

## Index

- **[Nmap](#nmap)** - Network reconnaissance and vulnerability research
  - [Nmap to MindMap](#nmap-to-mindmap-link) - Convert Nmap XML to visual mindmaps
  - [vMiner - Vulnerability Miner](#vminer---vulnerability-miner-link) - Automated CVE/exploit research
  - [Generate URLs from Nmap](#generate-urls-from-nmap-link) - Extract web service URLs
  - [Generate URLs for VHosts in Scope](#generate-urls-for-vhosts-in-scope-link) - Cross-reference hostnames with scan results
  - [Extract Software Versions from Nmap](#extract-software-versions-from-nmap-link) - Export detected software versions

- **[Infrastructure Analysis](#infrastructure-analysis)** - Large-scale reconnaissance
  - [HTTPx CSV Parser and Analyzer](#httpx-csv-parser-and-analyzer-link) - Advanced web infrastructure analysis

- **[Crawlers](#crawlers)** - Web application mapping
  - [yCrawler - Web Application Crawler](#ycrawler---web-application-crawler-link) - Discover GET/POST parameters

- **[Passwords](#passwords)** - Password audit analysis
  - [Domain Admin Password Cracker Analysis](#domain-admin-password-cracker-analysis) - Analyze cracked DA accounts

- **[Phishing](#phishing)** - Social engineering campaigns
  - [Better Phishing Frenzy Statistics](#better-phishing-frenzy-statistics-link) - Enhanced campaign analytics
  - [LinkedIn Email Scraper and Generator](#linkedin-email-scraper-and-generator-link) - Generate target email lists
  - [Email Address Extractor](#email-address-extractor-link) - Harvest emails from search engines

- **[Nessus](#nessus)** - Vulnerability assessment reporting
  - [Nessus Vulnerability Report Parser](#nessus-vulnerability-report-parser-link) - Professional vulnerability reports
  - [Nessus Compliance Report Parser](#nessus-compliance-report-parser-link) - Compliance audit reports

- **[Miscellaneous](#miscellaneous)** - Specialized tools
  - [SQL Injection Exploit Modifier](#sql-injection-exploit-modifier-link) - Standardize SQLi exploit output
  - [Source Code Grepper](#source-code-grepper-link) - Find user input in PHP code

---

## Nmap

### Nmap to MindMap [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/nmapToMindMap.pl)

Parses Nmap XML output and generates MindManager-compatible MindMap files with network topology visualization. Organizes discovered systems by IP address, hostname, open ports, service versions, and OS fingerprinting results. Also creates statistical summaries of interesting services (FTP, SSH, Telnet, HTTP, RDP, MS-SQL, MySQL) for quick identification of attack surface.

Coded in November 2011.

### vMiner - Vulnerability Miner [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/vMiner.pl)

Automated vulnerability research tool that parses Nmap XML output, extracts software versions, and queries CVEDetails.com and SecurityFocus.com for known vulnerabilities and exploits. Supports filtering by CVSS score, vulnerability type, authentication requirements, and access vector. Generates comprehensive reports in TXT, HTML, and MindMap formats with exploit links, Metasploit modules, and remediation guidance.

This was coded around November 2013 out of frustration with manually researching vulnerabilities for every service discovered during assessments. The code is admittedly spaghetti-level but it worked reliably for automated vuln correlation.

### Generate URLs from Nmap [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/nmap_parser_export_txt_file_with_weburls.pl)

Parses Nmap XML output and automatically generates HTTP/HTTPS URLs for all discovered web services. Intelligently handles SSL/TLS detection, non-standard ports, and constructs properly formatted URLs for mass web application testing.

### Generate URLs for VHosts in Scope [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/nmap_parser.pl)

Cross-references a list of hostnames against Nmap scan results to identify which hostnames resolve to IPs that were already scanned. Automatically generates URLs for newly discovered virtual hosts, preventing redundant port scans and ensuring comprehensive coverage of in-scope web applications.

Useful when you discover additional hostnames mid-engagement that may point to already-scanned infrastructure.

### Extract Software Versions from Nmap [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/extract_software_version_from_nmap_xml.pl)

Simple parser that extracts all detected software products and versions from Nmap XML output into a clean list format for vulnerability research and reporting.

---

## Infrastructure Analysis

### HTTPx CSV Parser and Analyzer [Link](https://github.com/gosirys/Parsers/tree/main/Misc/infra-parse.pl)

Advanced parser for HTTPx CSV output designed for large-scale infrastructure reconnaissance. Aggregates and analyzes thousands of URLs by IP address, HTTP status code, content length, content type, page title, server banner, CDN provider, and detected technologies. Provides statistical analysis, search functionality, and identifies unique URLs based on response characteristics to reduce noise in large datasets.

Written in January 2023 during a large Synack target engagement with my friend caffeine.

---

## Crawlers

### yCrawler - Web Application Crawler [Link](https://github.com/gosirys/Parsers/tree/main/Crawlers/yCrawler.pl)

Full-featured web crawler that discovers all GET and POST input parameters on a website. Supports HTTP proxy, logging, domain-limited crawling, and extracts forms with all input fields. Designed to map application attack surface before manual testing.

Written on 17 February 2011.

---

## Passwords

### Domain Admin Password Cracker Analysis

Two companion scripts for analyzing password cracking results during Active Directory assessments:

1. **Show DA's usernames that had their hashes cracked** [Link](https://github.com/gosirys/Parsers/tree/main/Passwords/get_list_of_cracked_DA_pwds.pl): Takes a list of Domain Admin accounts and Hashcat output to identify which DA accounts had their passwords cracked

2. **Show DA's cracked passwords** [Link](https://github.com/gosirys/Parsers/tree/main/Passwords/get_pwds_of_crackedDAs.pl): Extracts the actual cleartext passwords for cracked Domain Admin accounts from Hashcat output

Essential for demonstrating high-impact findings in penetration test reports.

---

## Phishing

### Better Phishing Frenzy Statistics [Link](https://github.com/gosirys/Parsers/tree/main/Phishing/betterPhishingFrenzy.pl)

Enhanced analytics for Phishing Frenzy campaigns that correlate Apache access logs with campaign data to generate detailed statistics:
- Click timestamps, source IPs, and device fingerprints per victim
- Aggregated statistics showing click distribution patterns
- OS/device breakdown with percentages
- Multiple-click behavior analysis

Written around November-December 2016 because Phishing Frenzy's native reporting was insufficient for client deliverables.

### LinkedIn Email Scraper and Generator [Link](https://github.com/gosirys/Parsers/tree/main/Phishing/LinkedinEmailScraper.pl)

Scrapes Google search results for LinkedIn profiles of employees at a target company and generates email addresses based on configurable naming conventions. Supports 24 different email syntax patterns (firstname.lastname, f.lastname, etc.) for building targeted phishing lists.

Coded on 30 July 2015.

### Email Address Extractor [Link](https://github.com/gosirys/Parsers/tree/main/Phishing/mail_extractor.pl)

Legacy tool from 2010 or earlier that scrapes search engines for leaked email addresses of specific email providers. Supports both command-line and IRC bot modes for distributed OSINT gathering.

---

## Nessus

### Nessus Vulnerability Report Parser [Link](https://github.com/gosirys/Parsers/tree/main/Nessus/nessusParserVulnSoft.pl)

Comprehensive Nessus parser that generates professional vulnerability reports ready for MS Word. Creates two detailed tables:
1. Summary table with risk-sorted vulnerabilities, service counts, CVE counts, and exploit availability
2. Detailed appendix with full vulnerability descriptions, CVE links, solutions, and exploit information

Includes built-in logic to identify publicly exploited vulnerabilities (e.g., MS17-010/EternalBlue) that Nessus sometimes underreports. Filters by CVSS score and groups statistics by risk level and exploitability.

### Nessus Compliance Report Parser [Link](https://github.com/gosirys/Parsers/tree/main/Nessus/complianceAuditParser.pl)

Parses Nessus compliance audit scans (CIS benchmarks, etc.) and generates human-friendly HTML reports with clean tables showing failed policies, expected vs actual values, and system-specific results. Designed for quick copy-paste into MS Word for compliance deliverables.

---

## Miscellaneous

### SQL Injection Exploit Modifier [Link](https://github.com/gosirys/Parsers/tree/main/Misc/sql_string_modifier.pl)

Automatically modifies SQL injection exploit payloads to standardize output matching patterns. Wraps extracted data with consistent delimiters (`g0tpwn3dbyv6`) to enable reliable regex parsing in automated scanners. 

Originally coded to adapt proof-of-concept SQLi exploits for use in IRC-based vulnerability scanners.

### Source Code Grepper [Link](https://github.com/gosirys/Parsers/tree/main/Misc/grepper.pl)

Automated PHP source code scanner that searches for user-supplied input variables (`$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER`) as a starting point for manual source code review. Identifies potential injection points and generates a report of interesting code locations for security analysis.

---

## License

GNU GPL v2 or later (see individual script headers)
