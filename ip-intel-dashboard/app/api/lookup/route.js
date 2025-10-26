import { NextResponse } from 'next/server';
import axios from 'axios';
import { isIP } from 'validator';
import isIPInRange from 'ip-range-check';
import { checkVirusTotal, checkAbuseIPDB, scanPorts, findSubdomains, bruteForceSubdomains } from '../../utils/threatIntel';
import { analyzeThreat } from '../../utils/aiAnalysis';

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const target = searchParams.get('target');

    // Validate input
    if (!target || target.trim() === '') {
      return NextResponse.json(
        { error: 'Target is required' },
        { status: 400 }
      );
    }

    const targetTrimmed = target.trim();

    // Check if it's an IP address
    const isIPAddress = isIP(targetTrimmed);

    // If it's an IP, check for private ranges
    if (isIPAddress) {
      if (
        isIPInRange(targetTrimmed, '10.0.0.0/8') ||
        isIPInRange(targetTrimmed, '192.168.0.0/16') ||
        isIPInRange(targetTrimmed, '172.16.0.0/12') ||
        targetTrimmed === '127.0.0.1' ||
        targetTrimmed === 'localhost'
      ) {
        return NextResponse.json(
          { error: 'Private/local IP addresses are not allowed' },
          { status: 400 }
        );
      }
    }

    const result = {
      target: targetTrimmed,
      geo: null,
      rdap: null,
      dns: null,
      http: null,
      virustotal: null,
      abuseipdb: null,
      ports: null,
      subdomains: null,
      aiAnalysis: null,
    };

    // Fetch Geo/ASN data
    try {
      const geoResponse = await axios.get(
        `http://ip-api.com/json/${targetTrimmed}?fields=status,message,query,country,regionName,city,isp,org,as,asname,lat,lon`,
        { timeout: 5000 }
      );
      if (geoResponse.data.status === 'success') {
        result.geo = geoResponse.data;
      } else {
        result.geo = { error: geoResponse.data.message || 'No data available' };
      }
    } catch (error) {
      result.geo = { error: 'Failed to fetch geo data' };
    }

    // Fetch RDAP data
    try {
      const rdapResponse = await axios.get(
        `https://rdap.org/${isIPAddress ? 'ip' : 'domain'}/${targetTrimmed}`,
        { timeout: 5000 }
      );
      result.rdap = rdapResponse.data;
    } catch (error) {
      result.rdap = { error: 'Failed to fetch RDAP data' };
    }

    // Fetch DNS data via Cloudflare DoH
    try {
      const dnsResponse = await axios.get(
        `https://cloudflare-dns.com/dns-query?name=${targetTrimmed}&type=A`,
        {
          headers: { Accept: 'application/dns-json' },
          timeout: 5000,
        }
      );
      result.dns = dnsResponse.data;
    } catch (error) {
      result.dns = { error: 'Failed to fetch DNS data' };
    }

    // Fetch HTTP info
    try {
      const httpResponse = await axios.get(`http://${targetTrimmed}`, {
        timeout: 3000,
        validateStatus: () => true, // Accept all status codes
      });
      result.http = {
        status: httpResponse.status,
        server: httpResponse.headers['server'] || 'Unknown',
        headers: {
          'content-type': httpResponse.headers['content-type'],
          'x-powered-by': httpResponse.headers['x-powered-by'],
        },
      };
    } catch (error) {
      result.http = {
        error: error.code === 'ECONNREFUSED' ? 'Connection refused' : 'Failed to fetch HTTP data',
      };
    }

    // Fetch VirusTotal threat intelligence (only for IPs)
    if (isIPAddress) {
      try {
        result.virustotal = await checkVirusTotal(targetTrimmed);
      } catch (error) {
        result.virustotal = { error: 'Failed to fetch VirusTotal data' };
      }

      // Fetch AbuseIPDB data
      try {
        result.abuseipdb = await checkAbuseIPDB(targetTrimmed);
      } catch (error) {
        result.abuseipdb = { error: 'Failed to fetch AbuseIPDB data' };
      }

      // Scan ports
      try {
        result.ports = await scanPorts(targetTrimmed);
      } catch (error) {
        result.ports = { error: 'Failed to scan ports' };
      }
    }

    // Fetch subdomains (only for domains)
    if (!isIPAddress) {
      try {
        const ctSubdomains = await findSubdomains(targetTrimmed);
        const bruteForceResults = await bruteForceSubdomains(targetTrimmed);
        result.subdomains = [...new Set([...ctSubdomains, ...bruteForceResults])];
      } catch (error) {
        result.subdomains = { error: 'Failed to find subdomains' };
      }
    }

    // Run AI-powered threat analysis
    try {
      result.aiAnalysis = await analyzeThreat(result);
    } catch (error) {
      result.aiAnalysis = { error: 'Failed to analyze threat' };
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error('Lookup error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
