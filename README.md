# CyberShield — Advanced Web Security Scanner

A real-time web vulnerability scanner built for university security teams to audit university-owned websites.

## What It Does

- Checks Security Headers (CSP, HSTS, X-Frame-Options)
- Analyzes SSL/TLS Certificates (expiry, ciphers, self-signed)
- Checks DNS Security (SPF, DMARC records)
- Detects Sensitive Path Exposure (.git, .env, /admin, etc.)
- Scans Domain Reputation via VirusTotal API
- Checks Cookie Security Flags (Secure, HttpOnly, SameSite)
- Gets SSL Grade from SSL Labs (A+ to F)
- Detects Exposed Ports and Services

## Tech Stack

- **Backend:** Node.js + Express.js
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **External APIs:** VirusTotal, SSL Labs, Google DNS
- **HTTP Client:** axios
- **Database:** None (stateless, real-time scans)

## How to Run

### Step 1: Install Node.js
Download from [nodejs.org](https://nodejs.org)

### Step 2: Clone this repository
git clone https://github.com/Divj09/CyberShield.git
cd CyberShield

### Step 3: Install dependencies
npm install


### Step 4: Create .env file
Create a file called `.env` in the root folder with:
PORT=3000
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

Get a free VirusTotal API key at [virustotal.com](https://www.virustotal.com)

### Step 5: Start the server
node server.js

### Step 6: Open in browser
Go to `http://localhost:3000`

## Project Structure
CyberShield/
├── server.js (Backend - Node.js + Express)
├── package.json (Dependencies)
├── .gitignore (Ignored files)
├── public/
│ └── index.html (Frontend - UI + JS)
└── .env (API keys - not on GitHub)

## Important Note

This tool is for **authorized security testing only**. Only scan websites you own or have explicit permission to test. Unauthorized scanning may violate computer fraud laws.

## Built By

Divyansh 
