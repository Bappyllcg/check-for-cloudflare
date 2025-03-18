# Cloudflare Detector

A simple web-based tool to detect if a website is using Cloudflare services, including their CDN and SSL certificates.

## Features

- Detects Cloudflare presence on websites
- Identifies Cloudflare SSL certificates
- Multiple detection methods:
  - HTTP Headers analysis
  - Cookie detection
  - HTML content scanning
  - SSL certificate verification
  - Script and security feature detection

## How It Works

The tool performs multiple checks to determine if a website is using Cloudflare:

1. **Header Analysis**
   - CF-Ray
   - CF-Cache-Status
   - Server identification
   - Custom Cloudflare headers

2. **Cookie Detection**
   - Cloudflare-specific cookies (__cf_bm, __cflb)
   - Security tokens

3. **SSL Certificate Verification**
   - Checks for Cloudflare SSL certificates
   - Identifies Universal SSL usage

4. **Content Analysis**
   - Cloudflare script detection
   - Security challenge forms
   - Honeypot elements
   - General Cloudflare mentions

## Usage

1. Enter a website URL in the input field
2. Click "Scan" or press Enter
3. View the detailed results showing:
   - Overall Cloudflare status
   - SSL certificate status
   - Detailed evidence of Cloudflare usage

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Bappyllcg/check-for-cloudflare.git