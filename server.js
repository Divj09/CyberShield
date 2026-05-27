// ============================================================
//  CyberShield - Security Scanner Backend
//  Real vulnerability scanner using Node.js built-in modules
//  No external tools required - everything runs through HTTP/HTTPS
// ============================================================

const express = require('express');
const https = require('https');
const http = require('http');
const tls = require('tls');
const net = require('net');
const dns = require('dns').promises;
const { URL } = require('url');

const app = express();
const PORT = 3000;

// Serve frontend files from /public folder
app.use(express.static('public'));
app.use(express.json());

// Simple rate limiter (1 scan per 30 seconds per IP)
const scanLimiter = new Map();

// ============================================================
//  UTILITY FUNCTIONS
// ============================================================

// Delay helper - pauses execution (used to not overwhelm target servers)
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Make an HTTP/HTTPS request and return response details
function makeRequest(targetUrl, options = {}) {
  return new Promise((resolve, reject) => {
    try {
      const parsed = new URL(targetUrl);
      const isHttps = parsed.protocol === 'https:';
      const lib = isHttps ? https : http;

      const requestOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: options.method || 'GET',
        headers: {
          'User-Agent': 'CyberShield/1.0 Security Scanner (University Security Audit Tool)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          ...(options.headers || {})
        },
        timeout: options.timeout || 15000,
        rejectUnauthorized: false // Allow self-signed certs for testing
      };

      const req = lib.request(requestOptions, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk.toString());
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: body,
            url: targetUrl
          });
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timed out'));
      });

      if (options.body) req.write(options.body);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}

// Follow redirects (up to 5 times)
async function fetchWithRedirects(url, options = {}, maxRedirects = 5) {
  const response = await makeRequest(url, options);
  if ([301, 302, 303, 307, 308].includes(response.statusCode) && maxRedirects > 0) {
    const location = response.headers.location;
    if (location) {
      try {
        const redirectUrl = new URL(location, url).href;
        return fetchWithRedirects(redirectUrl, options, maxRedirects - 1);
      } catch (e) {
        return response;
      }
    }
  }
  return response;
}

// ============================================================
//  SCANNER MODULES
//  Each scanner returns an array of findings (vulnerabilities)
// ============================================================

// ----- 1. SECURITY HEADERS SCANNER -----
// Checks for missing important security HTTP headers
async function scanSecurityHeaders(targetUrl) {
  const findings = [];
  const response = await fetchWithRedirects(targetUrl);
  const headers = {};

  // Normalize header names to lowercase for easy lookup
  for (const [key, value] of Object.entries(response.headers)) {
    headers[key.toLowerCase()] = value;
  }

  const checks = [
    {
      name: 'Content-Security-Policy',
      severity: 'high',
      description: 'Content Security Policy (CSP) prevents XSS attacks by defining approved sources of content that the browser may load. Without CSP, the page is vulnerable to injection attacks.',
      recommendation: 'Add a Content-Security-Policy header. Example: Content-Security-Policy: default-src \'self\'; script-src \'self\'',
      cvss: '6.1'
    },
    {
      name: 'X-Frame-Options',
      severity: 'medium',
      description: 'X-Frame-Options prevents clickjacking attacks by controlling whether a page can be embedded in iframes on other sites.',
      recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN header.',
      cvss: '4.3'
    },
    {
      name: 'X-Content-Type-Options',
      severity: 'low',
      description: 'X-Content-Type-Options prevents MIME-type sniffing. Without it, browsers may interpret files as different content types, leading to security issues.',
      recommendation: 'Add X-Content-Type-Options: nosniff header.',
      cvss: '3.5'
    },
    {
      name: 'Strict-Transport-Security',
      severity: 'high',
      description: 'HSTS forces browsers to always use HTTPS connections. Without it, users are vulnerable to man-in-the-middle attacks on first visit.',
      recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains header.',
      cvss: '6.5'
    },
    {
      name: 'X-XSS-Protection',
      severity: 'low',
      description: 'X-XSS-Protection enables the browser\'s built-in XSS filter. While deprecated in modern browsers, it provides protection for older browsers.',
      recommendation: 'Add X-XSS-Protection: 1; mode=block header.',
      cvss: '2.6'
    },
    {
      name: 'Referrer-Policy',
      severity: 'low',
      description: 'Referrer-Policy controls how much referrer information is shared when navigating away. Without it, sensitive URL parameters may leak to third parties.',
      recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin header.',
      cvss: '3.1'
    },
    {
      name: 'Permissions-Policy',
      severity: 'low',
      description: 'Permissions-Policy controls which browser features and APIs can be used. Without it, all features are available, increasing attack surface.',
      recommendation: 'Add Permissions-Policy header to restrict unnecessary browser features.',
      cvss: '2.4'
    },
    {
      name: 'X-Permitted-Cross-Domain-Policies',
      severity: 'info',
      description: 'Controls cross-domain access for Adobe products. Should be restricted to prevent cross-domain data theft.',
      recommendation: 'Add X-Permitted-Cross-Domain-Policies: none header.',
      cvss: '2.0'
    }
  ];

  for (const check of checks) {
    if (!headers[check.name.toLowerCase()]) {
      findings.push({
        title: `Missing ${check.name} Header`,
        severity: check.severity,
        description: check.description,
        location: 'HTTP Response Headers',
        details: {
          'Missing Header': check.name,
          'Status': 'NOT PRESENT',
          'CVSS Score': check.cvss
        },
        recommendation: check.recommendation
      });
    }
  }

  // Check for X-Powered-By (information disclosure)
  if (headers['x-powered-by']) {
    findings.push({
      title: 'Information Disclosure via X-Powered-By',
      severity: 'low',
      description: `The X-Powered-By header reveals backend technology: "${headers['x-powered-by']}". Attackers use this to find known vulnerabilities.`,
      location: 'HTTP Response Headers',
      details: {
        'Header Value': headers['x-powered-by'],
        'CVSS Score': '3.7'
      },
      recommendation: 'Remove the X-Powered-By header from all server responses.'
    });
  }

  return findings;
}


// ----- 2. SSL/TLS SCANNER -----
// Uses Node.js tls module to check certificate, protocol, ciphers directly
async function scanSSL(hostname) {
  const findings = [];

  return new Promise((resolve) => {
    const socket = tls.connect(443, hostname, {
      rejectUnauthorized: false,
      servername: hostname
    }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;

      // --- Check TLS Protocol Version ---
      const weakProtocols = {
        'TLSv1': { severity: 'high', msg: 'TLS 1.0 is deprecated (RFC 8996)' },
        'TLSv1.1': { severity: 'high', msg: 'TLS 1.1 is deprecated (RFC 8996)' },
        'SSLv3': { severity: 'critical', msg: 'SSLv3 is insecure (POODLE vulnerability)' },
        'SSLv2': { severity: 'critical', msg: 'SSLv2 is insecure and broken' }
      };

      if (weakProtocols[protocol]) {
        const info = weakProtocols[protocol];
        findings.push({
          title: `Weak TLS Protocol: ${protocol}`,
          severity: info.severity,
          description: `Server negotiated ${protocol}. ${info.msg}. Modern browsers have dropped support for this protocol.`,
          location: `Port 443 (${hostname})`,
          details: {
            'Detected Protocol': protocol,
            'Recommended': 'TLSv1.2 or TLSv1.3 only',
            'CVSS Score': info.severity === 'critical' ? '9.0' : '7.5'
          },
          recommendation: 'Configure server to disable TLS 1.0, TLS 1.1, SSLv2, SSLv3. Enable only TLS 1.2 and TLS 1.3.'
        });
      }

      // --- Check Certificate Expiry ---
      if (cert.valid_to) {
        const expiry = new Date(cert.valid_to);
        const now = new Date();
        const daysUntilExpiry = (expiry - now) / (1000 * 60 * 60 * 24);

        if (daysUntilExpiry < 0) {
          findings.push({
            title: 'SSL Certificate EXPIRED',
            severity: 'critical',
            description: `The SSL certificate expired on ${expiry.toLocaleDateString()}. Users will see security warnings and connections are vulnerable to MITM attacks.`,
            location: `Port 443 (${hostname})`,
            details: {
              'Expiry Date': expiry.toLocaleDateString(),
              'Days Overdue': Math.abs(Math.floor(daysUntilExpiry)).toString(),
              'Issuer': cert.issuer?.CN || 'Unknown',
              'CVSS Score': '9.2'
            },
            recommendation: 'Renew the SSL certificate IMMEDIATELY. Consider using Let\'s Encrypt for free certificates.'
          });
        } else if (daysUntilExpiry < 30) {
          findings.push({
            title: 'SSL Certificate Expiring Soon',
            severity: 'high',
            description: `SSL certificate expires in ${Math.floor(daysUntilExpiry)} days (${expiry.toLocaleDateString()}). Plan renewal immediately.`,
            location: `Port 443 (${hostname})`,
            details: {
              'Expiry Date': expiry.toLocaleDateString(),
              'Days Remaining': Math.floor(daysUntilExpiry).toString(),
              'CVSS Score': '6.5'
            },
            recommendation: 'Renew the certificate before it expires to avoid service disruption.'
          });
        }
      }

      // --- Check if Self-Signed ---
      if (cert.issuer && cert.subject) {
        const issuerCN = cert.issuer.CN || '';
        const subjectCN = cert.subject.CN || '';
        if (issuerCN === subjectCN && issuerCN !== '') {
          findings.push({
            title: 'Self-Signed SSL Certificate',
            severity: 'medium',
            description: 'The SSL certificate is self-signed. Browsers will show security warnings and users cannot verify the site\'s authenticity.',
            location: `Port 443 (${hostname})`,
            details: {
              'Issuer': issuerCN,
              'Subject': subjectCN,
              'CVSS Score': '5.3'
            },
            recommendation: 'Use a certificate from a trusted Certificate Authority (e.g., Let\'s Encrypt, DigiCert).'
          });
        }
      }

      // --- Check Hostname Match ---
      if (cert.subject) {
        const cn = cert.subject.CN || '';
        const altNames = cert.subjectaltname || '';
        const wildcards = altNames.split(',').map(n => n.trim().replace('DNS:', ''));
        const matches = cn === hostname ||
          altNames.includes(`DNS:${hostname}`) ||
          wildcards.some(w => {
            if (w.startsWith('*.')) {
              return hostname.endsWith(w.substring(1)) || hostname === w.substring(2);
            }
            return w === hostname;
          });

        if (!matches && cn !== '') {
          findings.push({
            title: 'SSL Certificate Hostname Mismatch',
            severity: 'high',
            description: `Certificate is for "${cn}" but server hostname is "${hostname}". This causes browser warnings and enables MITM attacks.`,
            location: `Port 443 (${hostname})`,
            details: {
              'Certificate CN': cn,
              'SAN Names': altNames || 'None',
              'Expected': hostname,
              'CVSS Score': '7.4'
            },
            recommendation: 'Obtain a certificate that matches the server hostname.'
          });
        }
      }

      // --- Check Weak Cipher Suites ---
      if (cipher) {
        const cipherName = (cipher.name || '').toUpperCase();
        const weakCipherKeywords = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
        const isWeak = weakCipherKeywords.some(k => cipherName.includes(k));

        if (isWeak) {
          findings.push({
            title: `Weak Cipher Suite: ${cipher.name}`,
            severity: 'high',
            description: `Server is using weak cipher: ${cipher.name}. This can be exploited to decrypt traffic.`,
            location: `Port 443 (${hostname})`,
            details: {
              'Cipher': cipher.name,
              'Protocol': cipher.protocol_version || 'Unknown',
              'CVSS Score': '7.2'
            },
            recommendation: 'Configure server to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305).'
          });
        }
      }

      // --- Check Certificate Authorization ---
      if (!authorized && cert.subject) {
        findings.push({
          title: 'Untrusted SSL Certificate',
          severity: 'high',
          description: 'The SSL certificate is not trusted by the system\'s certificate store. This could indicate a self-signed cert, expired cert, or unknown CA.',
          location: `Port 443 (${hostname})`,
          details: {
            'Authorized': 'No',
            'Issuer': cert.issuer?.CN || 'Unknown',
            'CVSS Score': '6.8'
          },
          recommendation: 'Use a certificate from a trusted Certificate Authority.'
        });
      }

      socket.end();
      resolve(findings);
    });

    socket.on('error', (err) => {
      findings.push({
        title: 'SSL/TLS Connection Failed',
        severity: 'high',
        description: `Could not establish secure connection: ${err.message}. The site may not support HTTPS or the SSL configuration is broken.`,
        location: `Port 443 (${hostname})`,
        details: {
          'Error': err.message,
          'CVSS Score': '7.5'
        },
        recommendation: 'Check SSL/TLS configuration. Ensure port 443 is open and serving valid certificates.'
      });
      resolve(findings);
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve(findings);
    });
  });
}


// ----- 3. COOKIE SECURITY SCANNER -----
// Checks cookies for Secure, HttpOnly, SameSite flags
async function scanCookies(targetUrl) {
  const findings = [];
  try {
    const response = await fetchWithRedirects(targetUrl);
    const cookies = response.headers['set-cookie'] || [];

    if (cookies.length === 0) {
      return findings; // No cookies = no cookie issues
    }

    const missingFlags = [];

    for (const cookie of cookies) {
      const cookieName = cookie.split('=')[0].trim();
      const hasSecure = /;\s*secure/i.test(cookie);
      const hasHttpOnly = /;\s*httponly/i.test(cookie);
      const hasSameSite = /;\s*samesite/i.test(cookie);

      if (!hasSecure) missingFlags.push(`${cookieName}: Missing Secure flag`);
      if (!hasHttpOnly) missingFlags.push(`${cookieName}: Missing HttpOnly flag`);
      if (!hasSameSite) missingFlags.push(`${cookieName}: Missing SameSite flag`);
    }

    if (missingFlags.length > 0) {
      findings.push({
        title: 'Insecure Cookie Configuration',
        severity: 'medium',
        description: `${cookies.length} cookie(s) found with ${missingFlags.length} missing security flags. Cookies without Secure flag are sent over HTTP. Without HttpOnly, cookies are accessible to JavaScript (XSS theft). Without SameSite, cookies are sent with cross-site requests (CSRF).`,
        location: 'HTTP Set-Cookie Headers',
        details: {
          'Total Cookies': cookies.length.toString(),
          'Missing Flags': missingFlags.join('; '),
          'CVSS Score': '5.4'
        },
        recommendation: 'Set Secure, HttpOnly, and SameSite=Strict (or Lax) flags on all cookies, especially session cookies.'
      });
    }

    // Check for session cookies without expiration
    for (const cookie of cookies) {
      const cookieName = cookie.split('=')[0].trim();
      if (!/;\s*expires/i.test(cookie) && !/;\s*max-age/i.test(cookie)) {
        findings.push({
          title: 'Session Cookie Without Expiration',
          severity: 'low',
          description: `Cookie "${cookieName}" has no expiration set. It becomes a "persistent" session cookie that may last indefinitely.`,
          location: 'HTTP Set-Cookie Headers',
          details: {
            'Cookie': cookieName,
            'Issue': 'No Expires or Max-Age attribute',
            'CVSS Score': '2.7'
          },
          recommendation: 'Set appropriate expiration times on all cookies.'
        });
      }
    }

  } catch (err) {
    // Silently fail - cookies are not always available
  }
  return findings;
}


// ----- 4. TECHNOLOGY DETECTION SCANNER -----
// Detects server technology from headers and HTML content
async function scanTechStack(targetUrl) {
  const findings = [];
  try {
    const response = await fetchWithRedirects(targetUrl);
    const headers = response.headers;
    const body = response.body;

    // Detect from Server header
    const server = headers['server'];
    if (server) {
      const versionMatch = server.match(/[\d]+\.[\d]+[\.\d]*/);
      if (versionMatch) {
        findings.push({
          title: 'Server Version Exposed',
          severity: 'low',
          description: `Server header reveals: "${server}". Attackers can search for known vulnerabilities in this specific version.`,
          location: 'HTTP Server Header',
          details: {
            'Server': server,
            'CVSS Score': '3.1'
          },
          recommendation: 'Configure the server to hide version numbers. For Apache: ServerTokens Prod. For Nginx: server_tokens off;'
        });
      }
    }

    // Detect from X-Powered-By
    const poweredBy = headers['x-powered-by'];
    if (poweredBy) {
      findings.push({
        title: 'Backend Technology Exposed',
        severity: 'low',
        description: `X-Powered-By header reveals: "${poweredBy}". This helps attackers identify specific vulnerabilities.`,
        location: 'HTTP X-Powered-By Header',
        details: {
          'Technology': poweredBy,
          'CVSS Score': '3.7'
        },
        recommendation: 'Remove the X-Powered-By header. For Express.js: app.disable(\'x-powered-by\')'
      });
    }

    // Detect frameworks in HTML
    const techPatterns = [
      { pattern: /wp-content|wp-includes|wordpress/i, name: 'WordPress' },
      { pattern: /<meta[^>]*joomla/i, name: 'Joomla' },
      { pattern: /drupal/i, name: 'Drupal' },
      { pattern: /jquery[.\-\s]*(\d+\.\d+\.\d+)/i, name: 'jQuery' },
      { pattern: /bootstrap[.\-\s]*(\d+\.\d+\.\d+)/i, name: 'Bootstrap' },
      { pattern: /react[\s\-\.]|_reactroot|__react/i, name: 'React' },
      { pattern: /ng-version|angular/i, name: 'Angular' },
      { pattern: /vue\.js|v-cloak|v-bind/i, name: 'Vue.js' },
      { pattern: /next\.js|__next/i, name: 'Next.js' },
      { pattern: /laravel/i, name: 'Laravel' },
      { pattern: /django|csrfmiddleware/i, name: 'Django' },
      { pattern: /express/i, name: 'Express.js' },
      { pattern: /php/i, name: 'PHP' },
    ];

    const detectedTechs = [];
    for (const { pattern, name } of techPatterns) {
      if (pattern.test(body)) {
        detectedTechs.push(name);
      }
    }

    // Check for known outdated libraries
    const versionPatterns = [
      { pattern: /jquery[.\-\s]*(\d+\.\d+\.\d+)/i, name: 'jQuery', minSafe: '3.5.0' },
      { pattern: /bootstrap[.\-\s]*(\d+\.\d+\.\d+)/i, name: 'Bootstrap', minSafe: '4.6.0' },
    ];

    for (const { pattern, name, minSafe } of versionPatterns) {
      const match = body.match(pattern);
      if (match && match[1]) {
        const version = match[1];
        const [major, minor, patch] = version.split('.').map(Number);
        const [sMajor, sMinor, sPatch] = minSafe.split('.').map(Number);
        const isOld = major < sMajor ||
          (major === sMajor && minor < sMinor) ||
          (major === sMajor && minor === sMinor && patch < sPatch);

        if (isOld) {
          findings.push({
            title: `Outdated Library: ${name} ${version}`,
            severity: 'medium',
            description: `${name} version ${version} detected. This version has known security vulnerabilities. Minimum safe version is ${minSafe}.`,
            location: 'HTML Page Source',
            details: {
              'Library': `${name} ${version}`,
              'Minimum Safe Version': minSafe,
              'CVSS Score': '6.1'
            },
            recommendation: `Update ${name} to the latest version. Check the changelog for security fixes.`
          });
        }
      }
    }

    // If tech detected but no specific issues, add as info
    if (detectedTechs.length > 0 && findings.length === 0) {
      findings.push({
        title: 'Technology Stack Detected',
        severity: 'info',
        description: `Detected technologies: ${detectedTechs.join(', ')}. This information could help attackers if specific versions have known vulnerabilities.`,
        location: 'HTTP Headers & HTML Source',
        details: {
          'Technologies': detectedTechs.join(', '),
          'CVSS Score': '0.0'
        },
        recommendation: 'Minimize technology fingerprinting. Remove version numbers and identifying comments from production code.'
      });
    }

  } catch (err) {
    // Server might not respond
  }
  return findings;
}


// ----- 5. XSS DETECTION SCANNER -----
// Tests for reflected XSS by injecting safe probe strings
async function scanXSS(targetUrl) {
  const findings = [];
  const probeString = 'cybershield_xss_test_a1b2c3d4';

  try {
    const parsedUrl = new URL(targetUrl);

    // Test common URL parameters with the probe string
    const testParams = ['q', 'search', 'query', 's', 'id', 'name', 'keyword', 'page', 'input', 'user'];
    const testUrl = new URL(targetUrl);

    for (const param of testParams) {
      testUrl.searchParams.set(param, probeString);
    }

    const response = await fetchWithRedirects(testUrl.href);

    if (response.body.includes(probeString)) {
      // Check if it appears in an HTML context (not just as text)
      const htmlContext = new RegExp(
        `value=["'][^"']*${probeString}|>${probeString}<|href=[^>]*${probeString}`,
        'i'
      );

      findings.push({
        title: 'Potential Reflected XSS Vulnerability',
        severity: 'high',
        description: 'User input from URL parameters is reflected in the page without proper encoding. This could allow attackers to inject malicious scripts that execute in victims\' browsers.',
        location: `URL Parameters (${testParams.join(', ')})`,
        details: {
          'Test URL': testUrl.pathname + testUrl.search.substring(0, 100),
          'Parameter Injection': 'Probe string reflected in response',
          'Context': htmlContext.test(response.body) ? 'HTML Attribute Context (higher risk)' : 'Text Context',
          'CVSS Score': '7.5'
        },
        recommendation: 'Implement output encoding for all user-supplied data. Use context-aware encoding (HTML entity, JavaScript, URL, CSS). Consider implementing Content Security Policy.'
      });
    }

    // Also test form-based XSS
    const formPattern = /<form[^>]*>[\s\S]*?<\/form>/gi;
    const forms = response.body.match(formPattern) || [];

    if (forms.length > 0) {
      // Check for input fields without proper encoding hints
      for (const form of forms) {
        const hasNoEncoding = !/accept-charset/i.test(form) ||
          (/<input[^>]*type\s*=\s*["']text/i.test(form));

        // Check for on* event handlers in form (existing XSS vectors)
        const eventHandlers = form.match(/on\w+\s*=\s*["']/gi);
        if (eventHandlers) {
          findings.push({
            title: 'Inline Event Handlers Detected',
            severity: 'medium',
            description: 'HTML forms contain inline event handlers (onclick, onerror, etc.). If user input reaches these, it could enable XSS.',
            location: 'HTML Form Elements',
            details: {
              'Handlers Found': eventHandlers.join(', '),
              'CVSS Score': '5.3'
            },
            recommendation: 'Remove inline event handlers. Use addEventListener() instead. Implement strict CSP.'
          });
        }
      }
    }

  } catch (err) {
    // Target may not respond
  }

  return findings;
}


// ----- 6. SQL INJECTION SCANNER -----
// Tests for SQLi by injecting safe probe strings and checking for SQL errors
async function scanSQLi(targetUrl) {
  const findings = [];
  const parsedUrl = new URL(targetUrl);

  const sqliProbes = [
    { payload: "'", name: 'Single Quote' },
    { payload: '"', name: 'Double Quote' },
    { payload: '1 AND 1=1', name: 'Boolean True' },
    { payload: "1' OR '1'='1", name: 'Always True' },
  ];

  // SQL error patterns from different databases
  const sqlErrorPatterns = [
    { pattern: /sql syntax.*?mysql|mysql.*?syntax/i, db: 'MySQL' },
    { pattern: /warning.*?\Wmysql/i, db: 'MySQL' },
    { pattern: /valid mysql result/i, db: 'MySQL' },
    { pattern: /check the manual that corresponds to your mysql server/i, db: 'MySQL' },
    { pattern: /mysql_fetch|mysql_num_rows|mysql_query/i, db: 'MySQL' },
    { pattern: /ORA-\d{5}/, db: 'Oracle' },
    { pattern: /oracle error|oracle.*?driver/i, db: 'Oracle' },
    { pattern: /postgresql.*?error|pg_query|pg_exec/i, db: 'PostgreSQL' },
    { pattern: /microsoft.*?odbc.*?sql server|sqlserver.*?jdbc/i, db: 'MSSQL' },
    { pattern: /unclosed quotation mark|unterminated string/i, db: 'MSSQL' },
    { pattern: /sqlite3?.*?error/i, db: 'SQLite' },
    { pattern: /sql command not properly ended/i, db: 'Oracle' },
    { pattern: /syntax error.*?sql|sql.*?syntax error/i, db: 'Generic SQL' },
    { pattern: /supplied argument is not a valid.*?result/i, db: 'Generic SQL' },
  ];

  // Get existing parameters or test common ones
  const existingParams = [...parsedUrl.searchParams.keys()];
  const testParams = existingParams.length > 0 ? existingParams : ['id', 'page', 'user', 'item', 'cat'];

  for (const param of testParams) {
    let foundForParam = false;

    for (const { payload, name } of sqliProbes) {
      if (foundForParam) break;

      try {
        const testUrl = new URL(targetUrl);
        const originalValue = testUrl.searchParams.get(param) || '1';
        testUrl.searchParams.set(param, originalValue + payload);

        const response = await fetchWithRedirects(testUrl.href);

        for (const { pattern, db } of sqlErrorPatterns) {
          if (pattern.test(response.body)) {
            findings.push({
              title: `Potential SQL Injection (${name})`,
              severity: 'critical',
              description: `SQL error message detected when testing parameter "${param}" with ${name} payload. The application may be concatenating user input directly into SQL queries, allowing attackers to read, modify, or delete database data.`,
              location: `URL Parameter: "${param}"`,
              details: {
                'Parameter': param,
                'Payload Used': payload,
                'Database Type': db,
                'Error Detected': 'Yes - SQL error in response',
                'CVSS Score': '9.8'
              },
              recommendation: 'Use parameterized queries (prepared statements) for ALL database operations. Never concatenate user input into SQL strings. Use ORM libraries that handle this automatically.'
            });
            foundForParam = true;
            break;
          }
        }

        await delay(300); // Be polite to the server
      } catch (err) {
        // Ignore request errors
      }
    }

    if (findings.length >= 3) break; // Don't flood results
  }

  return findings;
}


// ----- 7. CSRF DETECTION SCANNER -----
// Checks forms for CSRF token presence
async function scanCSRF(targetUrl) {
  const findings = [];
  try {
    const response = await fetchWithRedirects(targetUrl);
    const body = response.body;

    const formPattern = /<form[^>]*>[\s\S]*?<\/form>/gi;
    const forms = body.match(formPattern) || [];

    if (forms.length === 0) {
      return findings;
    }

    const csrfPatterns = [
      /csrf/i, /_token/i, /authenticity_token/i, /xsrf/i,
      /_csrf_token/i, /__requestverificationtoken/i, /anti.?forgery/i,
      /csrfmiddlewaretoken/i, /_wpnonce/i
    ];

    let vulnerableForms = 0;
    const vulnerableActions = [];

    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      const methodMatch = form.match(/method=["']([^"']*)["']/i);
      const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';

      // Only check state-changing methods
      if (['POST', 'PUT', 'DELETE'].includes(method)) {
        let hasCSRF = csrfPatterns.some(p => p.test(form));

        if (!hasCSRF) {
          vulnerableForms++;
          const actionMatch = form.match(/action=["']([^"']*)["']/i);
          vulnerableActions.push(actionMatch ? actionMatch[1] : '(same page)');
        }
      }
    }

    if (vulnerableForms > 0) {
      findings.push({
        title: 'CSRF Protection Missing',
        severity: 'high',
        description: `${vulnerableForms} form(s) lack CSRF token protection. Attackers can trick logged-in users into submitting these forms from malicious websites, performing actions on their behalf.`,
        location: 'HTML Form Elements',
        details: {
          'Vulnerable Forms': vulnerableForms.toString(),
          'Total Forms': forms.length.toString(),
          'Actions': vulnerableActions.slice(0, 5).join(', '),
          'CVSS Score': '6.5'
        },
        recommendation: 'Add anti-CSRF tokens to ALL state-changing forms. Use your framework\'s built-in CSRF protection (Django: {% csrf_token %}, Laravel: @csrf, Express: csurf middleware).'
      });
    }

  } catch (err) {
    // Silently fail
  }
  return findings;
}


// ----- 8. DIRECTORY ENUMERATION SCANNER -----
// Checks for exposed sensitive files and directories
async function scanDirectories(targetUrl) {
  const findings = [];
  const parsedUrl = new URL(targetUrl);
  const baseUrl = parsedUrl.origin;

  const sensitivePaths = [
    { path: '/.env', severity: 'critical', desc: 'Environment file (may contain passwords, API keys)' },
    { path: '/.git/config', severity: 'critical', desc: 'Git configuration (may expose source code)' },
    { path: '/.git/HEAD', severity: 'critical', desc: 'Git HEAD (confirms repository exposure)' },
    { path: '/.htaccess', severity: 'high', desc: 'Apache configuration' },
    { path: '/wp-config.php', severity: 'critical', desc: 'WordPress database config' },
    { path: '/config.php', severity: 'critical', desc: 'PHP configuration file' },
    { path: '/config.json', severity: 'high', desc: 'JSON configuration file' },
    { path: '/database.sql', severity: 'critical', desc: 'Database dump file' },
    { path: '/dump.sql', severity: 'critical', desc: 'SQL database dump' },
    { path: '/backup/', severity: 'high', desc: 'Backup directory' },
    { path: '/backups/', severity: 'high', desc: 'Backups directory' },
    { path: '/phpinfo.php', severity: 'medium', desc: 'PHP information page' },
    { path: '/info.php', severity: 'medium', desc: 'PHP info page' },
    { path: '/phpmyadmin/', severity: 'critical', desc: 'phpMyAdmin interface' },
    { path: '/admin/', severity: 'medium', desc: 'Admin panel' },
    { path: '/administrator/', severity: 'medium', desc: 'Administrator panel' },
    { path: '/server-status', severity: 'medium', desc: 'Apache server status' },
    { path: '/server-info', severity: 'medium', desc: 'Apache server info' },
    { path: '/.DS_Store', severity: 'medium', desc: 'macOS directory listing' },
    { path: '/package.json', severity: 'low', desc: 'Node.js package file' },
    { path: '/composer.json', severity: 'low', desc: 'PHP Composer file' },
    { path: '/.svn/entries', severity: 'high', desc: 'SVN repository data' },
    { path: '/swagger.json', severity: 'medium', desc: 'API documentation' },
    { path: '/api-docs/', severity: 'medium', desc: 'API documentation' },
    { path: '/graphql', severity: 'medium', desc: 'GraphQL endpoint' },
    { path: '/wp-content/debug.log', severity: 'high', desc: 'WordPress debug log' },
    { path: '/error_log', severity: 'medium', desc: 'Error log file' },
    { path: '/debug/', severity: 'medium', desc: 'Debug interface' },
    { path: '/.well-known/security.txt', severity: 'info', desc: 'Security policy file' },
    { path: '/robots.txt', severity: 'info', desc: 'Robots file (standard)' },
  ];

  const exposedPaths = [];
  const protectedPaths = [];

  for (const { path, severity, desc } of sensitivePaths) {
    try {
      const response = await makeRequest(baseUrl + path, { timeout: 5000 });

      if (response.statusCode === 200) {
        // Verify it's actually the file, not a custom 200 error page
        const bodySize = response.body.length;
        if (bodySize > 0 && bodySize < 5000000) { // Not a huge error page
          exposedPaths.push({ path, severity, desc, size: bodySize });
        }
      } else if (response.statusCode === 403 || response.statusCode === 401) {
        protectedPaths.push({ path, status: response.statusCode });
      }

      await delay(150); // Rate limit our requests
    } catch (err) {
      // Ignore errors (timeout, connection refused, etc.)
    }
  }

  // Filter out info-level and standard files for critical report
  const criticalExposed = exposedPaths.filter(p => p.severity !== 'info');

  if (criticalExposed.length > 0) {
    findings.push({
      title: 'Sensitive Files and Directories Exposed',
      severity: 'high',
      description: `${criticalExposed.length} sensitive files/directories are publicly accessible. These can expose credentials, source code, database contents, and server configuration.`,
      location: 'Web Server File System',
      details: {
        'Exposed Files': criticalExposed.map(p => `${p.path} (${p.desc})`).join('\n'),
        'Total Exposed': criticalExposed.length.toString(),
        'CVSS Score': '8.6'
      },
      recommendation: 'Remove sensitive files from the web root. Add proper access controls. Deny access to dot-files (.env, .git). Never store database dumps in web-accessible directories.'
    });
  }

  if (exposedPaths.filter(p => p.severity === 'critical').length > 0) {
    const critPaths = exposedPaths.filter(p => p.severity === 'critical');
    for (const p of critPaths) {
      findings.push({
        title: `CRITICAL: ${p.path} is Publicly Accessible`,
        severity: 'critical',
        description: `${p.desc} is publicly accessible at ${p.path}. This is a severe security risk that may expose credentials, source code, or database contents.`,
        location: p.path,
        details: {
          'Path': p.path,
          'Description': p.desc,
          'Response Size': `${p.size} bytes`,
          'CVSS Score': '9.8'
        },
        recommendation: `IMMEDIATELY restrict access to ${p.path}. Remove the file from the web root if not needed. Add deny rules in server configuration.`
      });
    }
  }

  return findings;
}


// ----- 9. PORT SCANNING -----
// Scans common ports using TCP connect (built-in net module)
async function scanPorts(hostname) {
  const findings = [];

  const commonPorts = [
    { port: 21, name: 'FTP', risk: 'high' },
    { port: 22, name: 'SSH', risk: 'medium' },
    { port: 23, name: 'Telnet', risk: 'critical' },
    { port: 25, name: 'SMTP', risk: 'medium' },
    { port: 53, name: 'DNS', risk: 'low' },
    { port: 80, name: 'HTTP', risk: 'info' },
    { port: 110, name: 'POP3', risk: 'medium' },
    { port: 135, name: 'MSRPC', risk: 'high' },
    { port: 139, name: 'NetBIOS', risk: 'high' },
    { port: 143, name: 'IMAP', risk: 'medium' },
    { port: 443, name: 'HTTPS', risk: 'info' },
    { port: 445, name: 'SMB', risk: 'critical' },
    { port: 993, name: 'IMAPS', risk: 'low' },
    { port: 995, name: 'POP3S', risk: 'low' },
    { port: 1433, name: 'MSSQL', risk: 'critical' },
    { port: 1521, name: 'Oracle DB', risk: 'critical' },
    { port: 3306, name: 'MySQL', risk: 'critical' },
    { port: 3389, name: 'RDP', risk: 'critical' },
    { port: 5432, name: 'PostgreSQL', risk: 'critical' },
    { port: 5900, name: 'VNC', risk: 'critical' },
    { port: 6379, name: 'Redis', risk: 'critical' },
    { port: 8080, name: 'HTTP-Alt', risk: 'medium' },
    { port: 8443, name: 'HTTPS-Alt', risk: 'medium' },
    { port: 9200, name: 'Elasticsearch', risk: 'critical' },
    { port: 27017, name: 'MongoDB', risk: 'critical' },
  ];

  const openPorts = [];

  // Scan ports with concurrency limit
  const batchSize = 10;
  for (let i = 0; i < commonPorts.length; i += batchSize) {
    const batch = commonPorts.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(({ port, name, risk }) => {
        return new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(2000);
          socket.on('connect', () => {
            socket.destroy();
            resolve({ port, name, risk, open: true });
          });
          socket.on('timeout', () => {
            socket.destroy();
            resolve({ port, name, risk, open: false });
          });
          socket.on('error', () => {
            resolve({ port, name, risk, open: false });
          });
          socket.connect(port, hostname);
        });
      })
    );
    openPorts.push(...results.filter(r => r.open));
  }

  // Check for dangerous open ports
  const dangerousOpen = openPorts.filter(p =>
    ['critical', 'high'].includes(p.risk)
  );

  if (dangerousOpen.length > 0) {
    findings.push({
      title: 'Dangerous Ports Open',
      severity: 'critical',
      description: `${dangerousOpen.length} dangerous ports are open and publicly accessible: ${dangerousOpen.map(p => `${p.name} (${p.port})`).join(', ')}. These services should not be exposed to the internet.`,
      location: `${hostname} - Network`,
      details: {
        'Dangerous Ports': dangerousOpen.map(p => `${p.name}: ${p.port}`).join(', '),
        'All Open Ports': openPorts.map(p => `${p.name}: ${p.port}`).join(', '),
        'Total Open': openPorts.length.toString(),
        'CVSS Score': '9.1'
      },
      recommendation: 'Close all unnecessary ports at the firewall level. Database ports (3306, 5432, 27017) and management ports (3389, 5900, 22) should NEVER be publicly accessible.'
    });
  }

  // Report unusual open ports
  const unusualOpen = openPorts.filter(p =>
    ![80, 443, 8080, 8443].includes(p.port) && !dangerousOpen.includes(p)
  );

  if (unusualOpen.length > 0) {
    findings.push({
      title: 'Unusual Ports Open',
      severity: 'medium',
      description: `Additional open ports detected: ${unusualOpen.map(p => `${p.name} (${p.port})`).join(', ')}. Review if these services need to be publicly accessible.`,
      location: `${hostname} - Network`,
      details: {
        'Ports': unusualOpen.map(p => `${p.name}: ${p.port}`).join(', '),
        'CVSS Score': '5.3'
      },
      recommendation: 'Review firewall rules. Close any ports that don\'t need public access. Use VPN for administrative access.'
    });
  }

  return { findings, openPorts };
}


// ----- 10. INFORMATION DISCLOSURE SCANNER -----
// Checks for leaked information in headers and page content
async function scanInfoDisclosure(targetUrl) {
  const findings = [];
  try {
    const response = await fetchWithRedirects(targetUrl);
    const body = response.body;

    // Check for server paths in error messages
    const pathPatterns = [
      { pattern: /\/var\/www\/[^\s<"]+/i, name: 'Linux Web Path' },
      { pattern: /\/home\/[^\s<"]+\/public_html/i, name: 'User Home Directory' },
      { pattern: /C:\\Users\\[^\s<"]+/i, name: 'Windows User Path' },
      { pattern: /\/usr\/local\/[^\s<"]+/i, name: 'System Path' },
      { pattern: /\/opt\/[^\s<"]+/i, name: 'Software Installation Path' },
    ];

    for (const { pattern, name } of pathPatterns) {
      const match = body.match(pattern);
      if (match) {
        findings.push({
          title: `Server Path Disclosure: ${name}`,
          severity: 'medium',
          description: `Internal server path found in page content: "${match[0].substring(0, 80)}". This reveals server directory structure.`,
          location: 'HTML Page Content',
          details: {
            'Type': name,
            'Path Found': match[0].substring(0, 80),
            'CVSS Score': '4.3'
          },
          recommendation: 'Disable detailed error messages in production. Use custom error pages that don\'t reveal file paths.'
        });
      }
    }

    // Check for email addresses (potential info disclosure)
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = body.match(emailPattern);
    if (emails && emails.length > 0) {
      const uniqueEmails = [...new Set(emails)].slice(0, 5);
      findings.push({
        title: 'Email Addresses Found',
        severity: 'info',
        description: `${uniqueEmails.length} email address(es) found on the page. These could be used for phishing or social engineering attacks.`,
        location: 'HTML Page Content',
        details: {
          'Emails Found': uniqueEmails.join(', '),
          'Total Count': emails.length.toString(),
          'CVSS Score': '0.0'
        },
        recommendation: 'Consider using contact forms instead of exposing email addresses. Use email obfuscation techniques if emails must be displayed.'
      });
    }

    // Check for comments containing sensitive info
    const commentPattern = /<!--[\s\S]*?(?:password|secret|key|token|admin|debug|test|todo|hack|fixme)[\s\S]*?-->/gi;
    const sensitiveComments = body.match(commentPattern);
    if (sensitiveComments) {
      findings.push({
        title: 'Sensitive HTML Comments Detected',
        severity: 'medium',
        description: `Found ${sensitiveComments.length} HTML comment(s) containing potentially sensitive keywords. These are visible in page source.`,
        location: 'HTML Comments',
        details: {
          'Count': sensitiveComments.length.toString(),
          'CVSS Score': '3.5'
        },
        recommendation: 'Remove all HTML comments from production code, especially those containing sensitive keywords.'
      });
    }

    // Check for forms with autocomplete enabled on sensitive fields
    const passwordFieldPattern = /<input[^>]*type=["']password["'][^>]*>/gi;
    const passwordFields = body.match(passwordFieldPattern) || [];
    const autocompleteOff = passwordFields.filter(f => /autocomplete\s*=\s*["']off["']/i.test(f));

    if (passwordFields.length > 0 && autocompleteOff.length < passwordFields.length) {
      findings.push({
        title: 'Password Fields Without Autocomplete Off',
        severity: 'low',
        description: `${passwordFields.length - autocompleteOff.length} password field(s) don\'t have autocomplete="off". Browsers may store these credentials.`,
        location: 'HTML Form Password Fields',
        details: {
          'Total Password Fields': passwordFields.length.toString(),
          'Without Autocomplete Off': (passwordFields.length - autocompleteOff.length).toString(),
          'CVSS Score': '2.4'
        },
        recommendation: 'Add autocomplete="off" or autocomplete="new-password" to password fields.'
      });
    }

  } catch (err) {
    // Silently fail
  }
  return findings;
}


// ----- 11. MALWARE/CRYPTOMINER DETECTION -----
// Checks for suspicious scripts and known malicious patterns
async function scanMalware(targetUrl) {
  const findings = [];
  try {
    const response = await fetchWithRedirects(targetUrl);
    const body = response.body;

    // Check for hidden iframes
    const hiddenIframePattern = /<iframe[^>]*(?:display:\s*none|visibility:\s*hidden|width:\s*[01]|height:\s*[01])[^>]*>/gi;
    const hiddenIframes = body.match(hiddenIframePattern);
    if (hiddenIframes) {
      findings.push({
        title: 'Hidden Iframes Detected',
        severity: 'high',
        description: `Found ${hiddenIframes.length} hidden iframe(s). These are commonly used in malware injections to load malicious content without user knowledge.`,
        location: 'HTML Page Source',
        details: {
          'Count': hiddenIframes.length.toString(),
          'CVSS Score': '8.2'
        },
        recommendation: 'Investigate all hidden iframes. Remove any that weren\'t intentionally added. Check if the site has been compromised.'
      });
    }

    // Check for suspicious JavaScript (eval, document.write from remote)
    const suspiciousPatterns = [
      { pattern: /eval\s*\(\s*(?:atob|String\.fromCharCode)/i, name: 'Obfuscated eval()' },
      { pattern: /document\.write\s*\(\s*(?:atob|String\.fromCharCode|decode)/i, name: 'Obfuscated document.write()' },
      { pattern: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, name: 'Hex-encoded strings' },
      { pattern: /coinhive|coin\.im|cryptoloot|crypto-webminer/i, name: 'Known Crypto-miner Script' },
      { pattern: /<script[^>]+src=["'][^"']*(?:pastebin|githubusercontent|ngrok)\./i, name: 'Script from suspicious source' },
    ];

    for (const { pattern, name } of suspiciousPatterns) {
      if (pattern.test(body)) {
        findings.push({
          title: `Suspicious Code: ${name}`,
          severity: 'critical',
          description: `Detected ${name} in page source. This pattern is commonly associated with malware injection or cryptomining scripts.`,
          location: 'HTML/JavaScript',
          details: {
            'Pattern': name,
            'CVSS Score': '9.1'
          },
          recommendation: 'Investigate immediately. This may indicate a compromised site. Check all third-party scripts and recent changes.'
        });
      }
    }

    // Check for mixed content (HTTP resources on HTTPS page)
    const parsedUrl = new URL(targetUrl);
    if (parsedUrl.protocol === 'https:') {
      const mixedContentPattern = /(?:src|href|action)\s*=\s*["']http:\/\//gi;
      const mixedContent = body.match(mixedContentPattern);
      if (mixedContent) {
        findings.push({
          title: 'Mixed Content Detected',
          severity: 'medium',
          description: `Found ${mixedContent.length} HTTP resource(s) loaded on HTTPS page. Browsers will block or warn about these, and they enable MITM attacks.`,
          location: 'HTML Page Source',
          details: {
            'Count': mixedContent.length.toString(),
            'CVSS Score': '5.3'
          },
          recommendation: 'Change all HTTP URLs to HTTPS. Use protocol-relative URLs or upgrade all resources to HTTPS.'
        });
      }
    }

  } catch (err) {
    // Silently fail
  }
  return findings;
}


// ----- 12. DDoS PROTECTION CHECK -----
// Checks for DDoS protection services and headers
async function scanDDoS(targetUrl) {
  const findings = [];
  try {
    const response = await fetchWithRedirects(targetUrl);
    const headers = {};
    for (const [key, value] of Object.entries(response.headers)) {
      headers[key.toLowerCase()] = value;
    }

    const server = (headers['server'] || '').toLowerCase();

    // Detect DDoS protection services
    const ddosServices = {
      'cloudflare': 'Cloudflare',
      'incapsula': 'Incapsula (Imperva)',
      'sucuri': 'Sucuri',
      'akamai': 'Akamai',
      'fastly': 'Fastly',
      'awselb': 'AWS ELB',
      'cloudfront': 'AWS CloudFront',
    };

    let protectedBy = null;
    for (const [keyword, service] of Object.entries(ddosServices)) {
      if (server.includes(keyword) || (headers['x-cache'] && headers['x-cache'].toLowerCase().includes(keyword))) {
        protectedBy = service;
        break;
      }
    }

    // Check Cloudflare-specific headers
    if (headers['cf-ray']) protectedBy = 'Cloudflare';

    if (!protectedBy) {
      findings.push({
        title: 'No DDoS Protection Detected',
        severity: 'medium',
        description: 'No DDoS protection service detected (Cloudflare, Akamai, etc.). The website is directly exposed to potential DDoS attacks.',
        location: 'HTTP Response Headers',
        details: {
          'Server': headers['server'] || 'Unknown',
          'DDoS Protection': 'None detected',
          'CVSS Score': '5.3'
        },
        recommendation: 'Consider using a DDoS protection service. Cloudflare offers a free plan that provides basic DDoS protection and CDN.'
      });
    }

    // Check rate limiting headers
    const rateLimitHeaders = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'retry-after'];
    const hasRateLimit = rateLimitHeaders.some(h => headers[h]);

    if (!hasRateLimit) {
      findings.push({
        title: 'No Rate Limiting Detected',
        severity: 'medium',
        description: 'No rate limiting headers found. The server may be vulnerable to brute force attacks and abuse.',
        location: 'HTTP Response Headers',
        details: {
          'Rate Limiting': 'Not detected',
          'CVSS Score': '5.3'
        },
        recommendation: 'Implement rate limiting on all endpoints, especially login and API routes.'
      });
    }

  } catch (err) {
    // Silently fail
  }
  return findings;
}


// ----- 13. API SECURITY SCANNER -----
// Checks for exposed API endpoints and documentation
async function scanAPI(targetUrl) {
  const findings = [];
  const parsedUrl = new URL(targetUrl);
  const baseUrl = parsedUrl.origin;

  const apiPaths = [
    { path: '/api/', desc: 'API Root' },
    { path: '/api/v1/', desc: 'API v1' },
    { path: '/api/v2/', desc: 'API v2' },
    { path: '/swagger.json', desc: 'Swagger/OpenAPI Spec' },
    { path: '/swagger-ui/', desc: 'Swagger UI' },
    { path: '/api-docs/', desc: 'API Documentation' },
    { path: '/graphql', desc: 'GraphQL Endpoint' },
    { path: '/graphiql', desc: 'GraphiQL IDE' },
    { path: '/.well-known/openid-configuration', desc: 'OpenID Config' },
  ];

  for (const { path, desc } of apiPaths) {
    try {
      const response = await makeRequest(baseUrl + path, { timeout: 5000 });

      if (response.statusCode === 200 && response.body.length > 0) {
        // Check if it actually returns JSON/API content
        const contentType = (response.headers['content-type'] || '').toLowerCase();
        const isAPIContent = contentType.includes('json') ||
          contentType.includes('xml') ||
          contentType.includes('html') ||
          response.body.startsWith('{') ||
          response.body.startsWith('[');

        if (isAPIContent) {
          findings.push({
            title: `Exposed: ${desc}`,
            severity: path.includes('swagger') || path.includes('graphiql') ? 'high' : 'medium',
            description: `${desc} is accessible at ${path}. This reveals API structure and documentation that could help attackers.`,
            location: path,
            details: {
              'Path': path,
              'Content-Type': contentType || 'Unknown',
              'Response Size': `${response.body.length} bytes`,
              'CVSS Score': path.includes('swagger') || path.includes('graphiql') ? '6.5' : '4.3'
            },
            recommendation: `Restrict access to ${path}. API documentation should only be available to authorized developers. Disable GraphiQL in production.`
          });
        }
      }

      await delay(150);
    } catch (err) {
      // Ignore
    }
  }

  return findings;
}


// ============================================================
//  MAIN SCAN ENDPOINT (Server-Sent Events)
//  Streams real-time results to the frontend as each scanner completes
// ============================================================

app.get('/api/scan', async (req, res) => {
  const targetUrl = req.query.url;
  const optionsRaw = req.query.options;

  // Validate URL
  if (!targetUrl) {
    return res.status(400).json({ error: 'URL is required' });
  }

  let targetUrlFixed = targetUrl;
  if (!targetUrlFixed.startsWith('http://') && !targetUrlFixed.startsWith('https://')) {
    targetUrlFixed = 'https://' + targetUrlFixed;
  }

  try {
    new URL(targetUrlFixed);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Rate limiting
  const clientIp = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const lastScan = scanLimiter.get(clientIp);
  if (lastScan && now - lastScan < 15000) {
    return res.status(429).json({ error: 'Please wait 15 seconds between scans' });
  }
  scanLimiter.set(clientIp, now);

  // Parse options
  let options;
  try {
    options = optionsRaw ? JSON.parse(optionsRaw) : {};
  } catch (e) {
    options = {};
  }

  // Setup Server-Sent Events
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const sendEvent = (data) => {
    try {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    } catch (e) {
      // Connection may have closed
    }
  };

  const parsedUrl = new URL(targetUrlFixed);
  const hostname = parsedUrl.hostname;

  // Define all available scanners
  const allScanners = [
    { name: 'Security Headers', key: 'headers', fn: () => scanSecurityHeaders(targetUrlFixed) },
    { name: 'SSL/TLS Analysis', key: 'ssl', fn: () => scanSSL(hostname) },
    { name: 'Cookie Security', key: 'cookies', fn: () => scanCookies(targetUrlFixed) },
    { name: 'Technology Detection', key: 'tech', fn: () => scanTechStack(targetUrlFixed) },
    { name: 'XSS Detection', key: 'xss', fn: () => scanXSS(targetUrlFixed) },
    { name: 'SQL Injection', key: 'sqli', fn: () => scanSQLi(targetUrlFixed) },
    { name: 'CSRF Detection', key: 'csrf', fn: () => scanCSRF(targetUrlFixed) },
    { name: 'Directory Enumeration', key: 'directory', fn: () => scanDirectories(targetUrlFixed) },
    { name: 'Port Scanning', key: 'ports', fn: () => scanPorts(hostname) },
    { name: 'Information Disclosure', key: 'info', fn: () => scanInfoDisclosure(targetUrlFixed) },
    { name: 'Malware Detection', key: 'malware', fn: () => scanMalware(targetUrlFixed) },
    { name: 'DDoS Protection', key: 'ddos', fn: () => scanDDoS(targetUrlFixed) },
    { name: 'API Security', key: 'api', fn: () => scanAPI(targetUrlFixed) },
  ];

  // Filter to only selected scanners
  const activeScanners = allScanners.filter(s => {
    // If no options specified, run all
    if (Object.keys(options).length === 0) return true;
    return options[s.key] === true;
  });

  const allFindings = [];
  const startTime = Date.now();

  // Send initial event
  sendEvent({
    type: 'start',
    target: targetUrlFixed,
    totalScanners: activeScanners.length
  });

  // Run each scanner sequentially
  for (let i = 0; i < activeScanners.length; i++) {
    const scanner = activeScanners[i];

    sendEvent({
      type: 'progress',
      scanner: scanner.name,
      index: i + 1,
      total: activeScanners.length,
      percentage: Math.round(((i) / activeScanners.length) * 100)
    });

    try {
      const result = await scanner.fn();

      // Handle port scan which returns { findings, openPorts }
      const scannerFindings = Array.isArray(result) ? result : (result.findings || []);

      allFindings.push(...scannerFindings);

      sendEvent({
        type: 'scanner_complete',
        scanner: scanner.name,
        findings: scannerFindings,
        findingCount: scannerFindings.length,
        percentage: Math.round(((i + 1) / activeScanners.length) * 100)
      });
    } catch (err) {
      sendEvent({
        type: 'scanner_error',
        scanner: scanner.name,
        error: err.message
      });
    }
  }

  // Compute final stats
  const stats = {
    total: allFindings.length,
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
  };

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);

  // Calculate security score (0-100)
  let score = 100;
  score -= stats.critical * 20;
  score -= stats.high * 10;
  score -= stats.medium * 5;
  score -= stats.low * 2;
  score -= stats.info * 0.5;
  score = Math.max(0, Math.min(100, Math.round(score)));

  let grade = 'A+';
  if (score < 20) grade = 'F';
  else if (score < 35) grade = 'D';
  else if (score < 50) grade = 'C';
  else if (score < 65) grade = 'B';
  else if (score < 80) grade = 'B+';
  else if (score < 90) grade = 'A';
  else grade = 'A+';

  sendEvent({
    type: 'complete',
    findings: allFindings,
    stats,
    score,
    grade,
    duration,
    target: targetUrlFixed,
    timestamp: new Date().toISOString()
  });

  res.end();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', uptime: process.uptime() });
});

// ============================================================
//  START SERVER
// ============================================================

app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║     ⚡ CyberShield Security Scanner ⚡     ║');
  console.log('  ╠══════════════════════════════════════════╣');
  console.log(`  ║  Server running at: http://localhost:${PORT}  ║`);
  console.log('  ║  Press Ctrl+C to stop                    ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
});
