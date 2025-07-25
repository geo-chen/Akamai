# Akamai

## CVE-2025-54568 - Rate-Limit Bypass via Edge Hopping 

### Summary

**Akamai Rate Control alpha before 2025 allows attackers to send requests above the stipulated thresholds because the rate is measured separately for each edge node.**

Attackers were able to bypass rate-limiting by distributing high-volume requests to different Akamai edge servers. Because the states of the rate thresholds were maintained locally within the edges, attackers are able to hit a target at high velocity that's well above the stipulated thresholds. 

### Description

A vulnerability was identified in Akamai's Rate Controls where the rate control states were maintained locally on their edges, allowing attackers to bypass rate-limiting by edge hopping - that is, rotating between different Akamai edge servers. 
This is because rate thresholds are counted per edge node (edge-specific) as opposed to an aggregated global state.  

### Disclosure
We have informed Akamai on 24 October 2024 and requested for global aggregation. Akamai acknowledged and shared that it is a known gap. A fix has since been released to Akamai's customers and is currently in beta mode. The release notes can be viewed here (requires login; only for Akamai customers):
http://techdocs.akamai.com/app-api-protector/docs/improved-rate-accounting

### Vulnerability Type

Other - Rate-limit bypass

### Vendor of Product

Akamai

### Affected Product Code Base

Akamai Rate Control, version alpha

### Affected Component

Akamai Rate Controls

### Attack Vectors
An attacker exploiting this vulnerability can rotate across Akamai edge servers to bypass rate-limiting. 

### Discoverer

George Chen, Chee Peng Tan, Pulkit Arya
