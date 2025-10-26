import axios from 'axios';
// Note: portscanner needs to be imported differently
let portscanner;
try {
  portscanner = require('portscanner');
} catch (e) {
  console.warn('portscanner not available');
}

// VirusTotal API (free tier: 4 requests per minute)
export async function checkVirusTotal(ip) {
  try {
    // For demo purposes, return mock data
    // In production, use: https://www.virustotal.com/api/v3/ip_addresses/{ip}
    // You'll need a free API key from virustotal.com
    const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: {
        'X-Apikey': process.env.VIRUSTOTAL_API_KEY || ''
      },
      timeout: 5000
    });
    return response.data;
  } catch (error) {
    // Return mock data if API fails
    return {
      success: false,
      message: 'VirusTotal API not configured or rate limited',
      mock: true
    };
  }
}

// AbuseIPDB API (free tier: 1000 requests per day)
export async function checkAbuseIPDB(ip) {
  try {
    const response = await axios.get(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`,
      {
        headers: {
          'Key': process.env.ABUSEIPDB_API_KEY || '',
          'Accept': 'application/json'
        },
        timeout: 5000
      }
    );
    return response.data;
  } catch (error) {
    return {
      success: false,
      message: 'AbuseIPDB API not configured or rate limited',
      mock: true
    };
  }
}

// Certificate Transparency search for subdomains
export async function findSubdomains(domain) {
  try {
    const response = await axios.get(
      `https://crt.sh/?q=${domain}&output=json`,
      { timeout: 5000 }
    );
    
    const certs = response.data;
    const subdomains = new Set();
    
    certs.forEach(cert => {
      if (cert.common_name) {
        if (cert.common_name.includes(domain)) {
          subdomains.add(cert.common_name);
        }
      }
      if (cert.name_value) {
        cert.name_value.split('\n').forEach(name => {
          if (name.includes(domain)) {
            subdomains.add(name);
          }
        });
      }
    });
    
    return Array.from(subdomains).slice(0, 20);
  } catch (error) {
    return [];
  }
}

// Port scanning using portscanner
export async function scanPorts(ip) {
  try {
    if (!portscanner) {
      return [];
    }
    
    // Scan common ports
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379];
    const openPorts = [];
    
    // Limit to 10 ports for speed
    const portsToScan = commonPorts.slice(0, 10);
    
    for (const port of portsToScan) {
      try {
        const status = await portscanner.checkPortStatus(port, ip, { timeout: 3000 });
        if (status === 'open') {
          openPorts.push({ port, status: 'open' });
        }
      } catch (error) {
        // Port closed or filtered
      }
    }
    
    return openPorts;
  } catch (error) {
    return [];
  }
}

// DNS brute force for common subdomains
export async function bruteForceSubdomains(domain) {
  try {
    const commonSubdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
                              'test', 'staging', 'dev', 'blog', 'shop', 'store', 'api', 'cdn', 'admin', 
                              'secure', 'vpn', 'support', 'help', 'portal', 'app', 'apps', 'login'];
    
    const found = [];
    
    // Check first 10 common subdomains (to avoid rate limiting)
    for (const subdomain of commonSubdomains.slice(0, 10)) {
      try {
        const dnsResponse = await axios.get(
          `https://cloudflare-dns.com/dns-query?name=${subdomain}.${domain}&type=A`,
          {
            headers: { Accept: 'application/dns-json' },
            timeout: 2000
          }
        );
        
        if (dnsResponse.data && dnsResponse.data.Answer && dnsResponse.data.Answer.length > 0) {
          found.push(`${subdomain}.${domain}`);
        }
      } catch (error) {
        // Subdomain doesn't exist
      }
    }
    
    return found;
  } catch (error) {
    return [];
  }
}
