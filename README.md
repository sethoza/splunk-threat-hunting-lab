# Splunk Threat Hunting Lab
### BOTSv3 Investigation Series – Cloud Misconfiguration & S3 Exposure

**Author:** Alvin Espinoza  
**Focus:** SOC-style investigation using Splunk + AWS logs  
**Status:** Active portfolio project (more investigations will be added)

---

## Why This Project Exists

I built this lab to practice the real workflow of a SOC analyst:

- Receive a question or alert
- Hunt through logs
- Refine searches when the first ones fail
- Dig into nested fields
- Document findings clearly

This is not a walkthrough dump. It is a record of how I investigated. 
---

## Skills Demonstrated

- Splunk Search Processing Language (SPL)
- AWS CloudTrail analysis
- S3 access log investigation
- Identifying public bucket misconfigurations
- Tracing file uploads during an exposure window
- Structured documentation of both successes and roadblocks

---

## Investigations Completed (v1)

| # | Question | Finding |
|---|----------|---------|
| 200 | IAM users that accessed AWS services | bstoll, btun, splunk_access, web_admin |
| 201 | Field to detect API calls without MFA | `userIdentity.sessionContext.attributes.mfaAuthenticated` |
| 202 | Processor number on web servers | i7-4980HQ |
| 203 | Event ID that made the S3 bucket public | ab45689d-69cd-41e7-8705-5350402cf7ac |
| 204 | Name of the publicly accessible bucket | frothlywebcode |
| 205 | Text file uploaded while bucket was public | OPEN_BUCKET_PLEASE_FIX.txt |
| 206 | Size of the .tar.gz uploaded while public | 2.93 MB |

---

## Core Story: Public S3 Bucket Exposure

An IAM user accidentally granted public access (`AllUsers`) to the S3 bucket `frothlywebcode`.  

While the bucket was public, two objects were uploaded:

- `OPEN_BUCKET_PLEASE_FIX.txt`
- `frothly_html_memcached.tar.gz` (2.93 MB)

This is a classic cloud misconfiguration scenario. The investigation required pivoting between CloudTrail management events and S3 access logs, expanding nested JSON, and calculating impact from raw log values.

Full write up available in the report:  
Full write-up: [01 – AWS S3 Public Bucket Investigation](./labs/01-aws-s3-publicbucket.md)

---

## Investigation Path & Roadblocks

Not every search worked on the first try. Key lessons:

- Searching for the word “public” returned nothing → had to target `PutBucketAcl`
- File uploads did not appear in CloudTrail → moved to `aws:s3:accesslogs`
- The critical `AllUsers` grant was buried deep in nested fields
- Object size had to be extracted from the raw access log line

Documenting the dead ends is intentional. Real investigations are iterative. Basically documenting the full investigation path, including the dead ends.

---

## Key Takeaways

- Public S3 buckets remain one of the highest-impact cloud risks
- Both management events and data events are required for full visibility
- Nested fields often contain the real evidence
- Clear documentation of the path taken matters as much as the final answer

---

## How to Reproduce

1. Install Splunk Enterprise (trial or developer license)
2. Ingest the official BOTSv3 dataset
3. Set time range to **All Time**
4. Search `index=botsv3`

---

## What’s Next

This is a living project. Additional investigations (endpoint, process, coin mining, etc.) will be added over time.
