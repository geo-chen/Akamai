# Akamai

## CVE-2025-30143 - WAF Bypass in Akamai ASE (Application Security Edge) due to Obfuscated Payload leading to Reflected XSS

### Summary
An issue was discovered in Akamai Application Security Edge (ASE) 1.
Rule 3000216 v1 allows XSS because variable chaining (e.g., a=alert; b=document; b=b.domain; a(b))
with URL encoding is not considered.

### Description

A vulnerability was identified in Akamai's Application Security Edge (ASE) prior to version 2 of WAF Rule 3000216 , where the rule was insufficiently equipped to detect certain obfuscated JavaScript patterns used in Reflected Cross-Site Scripting (XSS) attacks.
Specifically, the rule failed to identify scenarios where attackers utilized variable declarations, assignments, and obfuscation techniques, such as <REDACTED>.

The adaptive security engine underlying Rule 3000216 was overly
restrictive in its validation of JavaScript payloads, failing to
account for obfuscation strategies like variable chaining (e.g.,
a=alert; b=document; b=b.domain; a(b)) and their URL-encoded
equivalents (e.g., %0a for line breaks). As a result, attackers were able to craft malicious URLs that could evade detection by ASE and execute arbitrary JavaScript code in the context of a victim's browser. This could lead to sensitive information disclosure (e.g., session tokens, cookies) or unauthorized actions executed on behalf of the user.


### Disclosure
We have informed Akamai on 18 October 2024 and a global fix was released by Akamai to all its customers on 9 December 2024. While the fix is now rolled out globally, we want to disclose this vulnerability and encourage organizations using Akamai to retrospectively check back on any possible exploitation prior to 9 December 2024.


### Vulnerability Type

Cross Site Scripting (XSS)

### Vendor of Product

Akamai

### Affected Product Code Base

Application Security Edge (ASE) - v1

### Affected Component

Web Application Firewall 

### Attack Vectors
An attacker exploiting this vulnerability would inject malicious obfuscated JavaScript into a vulnerable parameter (e.g., URL query parameters). If the vulnerable web application reflected this input back to the user without sanitization, an attacker could trigger XSS by tricking the victim into clicking a malicious link or visiting a webpage embedding the payload.

https://techdocs.akamai.com/app-api-protector/changelog/dec-9-2024-waf-rule-updates

### Discoverer

George Chen, Chee Peng Tan, Pulkit Arya



