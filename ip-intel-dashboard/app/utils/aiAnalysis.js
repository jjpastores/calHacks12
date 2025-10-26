import { HfInference } from '@huggingface/inference';

const hf = new HfInference(process.env.HF_TOKEN || '');

export async function analyzeThreat(ipData) {
  try {
    // Skip AI analysis if no token (free tier - no key needed for testing)
    // For production, you can use HuggingFace Inference API or local model
    
    // Generate threat analysis from collected data
    const analysis = generateThreatAnalysis(ipData);
    
    return {
      riskScore: analysis.riskScore,
      severity: analysis.severity,
      summary: analysis.summary,
      indicators: analysis.indicators,
      recommendations: analysis.recommendations
    };
  } catch (error) {
    console.error('AI Analysis error:', error);
    return {
      riskScore: 5,
      severity: 'UNKNOWN',
      summary: 'Unable to analyze threat',
      indicators: [],
      recommendations: []
    };
  }
}

function generateThreatAnalysis(ipData) {
  const { geo, rdap, dns, http, virustotal, abuseipdb, ports, subdomains } = ipData;
  
  let riskScore = 0;
  const indicators = [];
  const recommendations = [];
  
  // Analyze Geo data
  if (geo && geo.country) {
    const highRiskCountries = ['RU', 'CN', 'KP', 'IR'];
    if (highRiskCountries.includes(geo.country)) {
      riskScore += 2;
      indicators.push(`High-risk country: ${geo.country}`);
    }
  }
  
  // Analyze RDAP/Whois
  if (rdap && rdap.org) {
    const suspiciousKeywords = ['privacy', 'proxy', 'vpn', 'anonymous'];
    const orgLower = rdap.org.toLowerCase();
    if (suspiciousKeywords.some(keyword => orgLower.includes(keyword))) {
      riskScore += 1;
      indicators.push('Suspicious organization naming pattern');
    }
  }
  
  // Analyze DNS
  if (dns && dns.Answer && dns.Answer.length === 0) {
    riskScore += 1;
    indicators.push('No DNS records found');
  }
  
  // Analyze HTTP headers
  if (http && http.status === 200) {
    if (http.server && http.server.toLowerCase().includes('cloudflare')) {
      riskScore += 1;
      indicators.push('Protected by Cloudflare (could hide origin)');
    }
  }
  
  // Analyze VirusTotal data
  if (virustotal && virustotal.data && virustotal.data.attributes) {
    const lastAnalysis = virustotal.data.attributes.last_analysis_stats;
    if (lastAnalysis && lastAnalysis.malicious > 0) {
      riskScore += 5;
      indicators.push(`${lastAnalysis.malicious} security vendors flagged this IP`);
    }
  }
  
  // Analyze AbuseIPDB data
  if (abuseipdb && abuseipdb.data) {
    if (abuseipdb.data.abuseConfidenceScore > 50) {
      riskScore += 4;
      indicators.push(`High abuse confidence score: ${abuseipdb.data.abuseConfidenceScore}%`);
    }
    if (abuseipdb.data.totalReports > 0) {
      riskScore += Math.min(abuseipdb.data.totalReports, 5);
      indicators.push(`${abuseipdb.data.totalReports} abuse reports`);
    }
  }
  
  // Analyze open ports
  if (ports && ports.length > 0) {
    const dangerousPorts = [22, 23, 135, 139, 445, 3389, 5432, 6379];
    const foundDangerous = ports.filter(p => dangerousPorts.includes(Number(p.port)));
    if (foundDangerous.length > 0) {
      riskScore += foundDangerous.length;
      indicators.push(`${foundDangerous.length} potentially dangerous ports open`);
      recommendations.push('Secure exposed services or close unnecessary ports');
    }
  }
  
  // Analyze subdomains
  if (subdomains && subdomains.length > 10) {
    riskScore += 1;
    indicators.push(`Large number of subdomains detected: ${subdomains.length}`);
  }
  
  // Determine severity
  let severity;
  if (riskScore >= 8) severity = 'CRITICAL';
  else if (riskScore >= 5) severity = 'HIGH';
  else if (riskScore >= 3) severity = 'MEDIUM';
  else if (riskScore >= 1) severity = 'LOW';
  else severity = 'MINIMAL';
  
  // Generate summary
  let summary = `Risk assessment for ${ipData.target}: `;
  summary += `Overall risk score of ${riskScore}/10 (${severity} severity). `;
  
  if (indicators.length > 0) {
    summary += `Key findings include: ${indicators.slice(0, 3).join(', ')}.`;
  }
  
  // Generate recommendations
  if (riskScore >= 7) {
    recommendations.push('Exercise extreme caution when interacting with this IP');
    recommendations.push('Consider blocking this IP at network perimeter');
  } else if (riskScore >= 5) {
    recommendations.push('Monitor this IP for suspicious activity');
    recommendations.push('Apply additional security controls if needed');
  } else if (riskScore >= 3) {
    recommendations.push('Conduct additional investigation if unexpected');
  } else {
    recommendations.push('IP appears relatively safe for normal operations');
  }
  
  return {
    riskScore: Math.min(riskScore, 10),
    severity,
    summary,
    indicators: indicators.slice(0, 5),
    recommendations
  };
}
