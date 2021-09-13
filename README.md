
## Nmap 

### Nmap to Mindmap [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/nmapToMindMap.txt)
Utility to convert Nmap's XML output into a Mindmap.
Not sure when this was coded.

### Generate URLs from Nmap [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/nmap_parser_export_txt_file_with_weburls.pl)
Another parser to generate URLs based on the web services discovered by Nmap.
Not sure when this was coded.

### Generate URLs for VHosts in scope from Nmap [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/nmap_parser.pl)
Utility to determine - based on a provided list of hostnames and an Nmap's scans result - which of the hostnames resolves to an IP address scanned my Nmap. This was coded to avoid having to perform ports scan on hosts which were already scanned as pointing to the same server.
One could have port scan results of IPs belonging to a company or simply systems in scope for the exercise, and then obtain additional hostnames that might potentially resolve to system in scope and that were already scanned with nmap. One could use this utility to compare any new hostname with the initial port's scan outpiut to discover new virtual hosts in scope systems and have all their URLs automatically generated.
Not sure when this was coded.

### Extract software versions from Nmap [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/extract_software_version_from_nmap_xml.pl)
Utility to extract software versions from an Nmap output scan.
Not sure when this was coded.
	

### Find known vulnerabilities against software detected by Nmap [Link](https://github.com/gosirys/Parsers/tree/main/Nmap/vMiner.pl)
Being tired of manually looking for known vulnerabilities/exploit codes for a given software version as reported by Nmap, brought me to code this tool around 2013.
I'm not sure it even works anymore and this is next level Spaghetti coding. However I remember it used to work quite well. 
Parsing an Nmap output file for software version, this tool would search on cvedetails for advisories and exploit codes. Supports filters (min CVSS score etc) and creates both an HTML report and Mindmap with the findings.

## Crawlers 

### A Web Crawler [Link](https://github.com/gosirys/Parsers/tree/main/Crawlers/yCrawler.txt)
My poor attempt at writing a web crawler. Written sometime in 2011.

## Passwords


### Show DA's cracked hashes [Link](https://github.com/gosirys/Parsers/tree/main/Passwords/get_pwds_of_crackedDAs.pl)
See passwords of cracked hashes belonging to Domain Admin users.

### Show DA's usernames that had their hashes cracked [Link](https://github.com/gosirys/Parsers/tree/main/Passwords/get_list_of_cracked_DA_pwds.pl)
Get the list of users in the Domain Admin group whose hashes were successfully cracked.

## Phishing

### Better stats from Phishing Frenzy [Link](https://github.com/gosirys/Parsers/tree/main/Phishing/betterPhishingFrenzy.pl)
Get more information from a Phishing compaign ran with Phishing Frenzy.
This would produce additional stats such as:
```
[email victim no#] EMAIL clicked X times from the following locations:
	[1] TIME: 30/Nov/2016:13:50:02 +1100 - FROM: 139.x.x.x - DEVICE: Win7
	[2] TIME: 30/Nov/2016:13:48:25 +1100 - FROM: 139.x.x.x - DEVICE: Win7	

Stats 2:

1 people clicked 15 times on the link
5 people clicked 11 times on the link
4 people clicked 10 times on the link
2 people clicked 9 times on the link
etc etc ..

Stats 3:

2122 (79.535%) clicks from Win7
369 (13.831%) clicks from iOS
79 (2.961%) clicks from Mac OS X
44 (1.649%) clicks from Win10.0
etc etc ..
```

### Email addresses extractor [Link](https://github.com/gosirys/Parsers/tree/main/Phishing/mail_extractor.txt)
Utility from 2010 or earlier to scrape search engines for leaked email addressed of a given mail provider.

### LinkedIn Email Scraper and Generator [Link](https://github.com/gosirys/Parsers/tree/main/Phishing/LinkedinEmailScraper.pl)
Scraper I built sometime around 2015 to parse google for LinkedIn results of employees of a given company and produce their email addresses following the email syntax in use by the company.

## Nessus

### Better stats from Nessus reports [Link](https://github.com/gosirys/Parsers/tree/main/Nessus/nessusParserVulnSoft.pl)
A Nessus parser to generate nice statistics and a breakdown and summary of vulnerability distribution, ready to copy and paste into MS-Word.

### Better Nessus Compliance Reports  [Link](https://github.com/gosirys/Parsers/tree/main/Nessus/complianceAuditParser.pl)
Nessus parser for Compliance/Audit scans to generate a human friendly report ready to be pasted in MS-Word.

## Misc

### SQL Injection exploits modifier to standarise matching patterns [Link](https://github.com/gosirys/Parsers/tree/main/Misc/sql_string_modifier.txt)
This was a small script I coded to automatically modify a given SQL Injection exploit payload to allow for an easier and uniformed way to parse extracted database rows from a vulnerable page. This was coded in an attempt to automaticallty adapt SQLIs PoC so that they could be used in my IRC Scanners.

### Source Code Grepper [Link](https://github.com/gosirys/Parsers/tree/main/Misc/grepper.txt)
A poor attempt at writing an automated source code scanner for PHP Applications aimed to find user-inputs throughout the code base. This expected to be followed by a manual source code analysis of the bits of code returned by the parser.
