'use client';

import { useState } from 'react';
import axios from 'axios';

export default function Home() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [data, setData] = useState(null);

  const handleAnalyze = async () => {
    if (!target.trim()) {
      setError('Please enter an IP address or domain name');
      return;
    }

    setLoading(true);
    setError('');
    setData(null);

    try {
      const response = await axios.get(`/api/lookup?target=${encodeURIComponent(target)}`);
      
      if (response.data.error) {
        setError(response.data.error);
      } else {
        setData(response.data);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to analyze target');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleAnalyze();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white">
      <div className="container mx-auto px-4 py-12 max-w-7xl">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-5xl font-bold mb-4 bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
            IP Intelligence Dashboard
          </h1>
          <p className="text-gray-400 text-lg">
            Discover public information about IP addresses and domains
          </p>
        </div>

        {/* Input Section */}
        <div className="max-w-2xl mx-auto mb-12">
          <div className="flex gap-4">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Enter IP address or domain (e.g., 8.8.8.8 or example.com)"
              className="flex-1 px-6 py-4 rounded-lg bg-gray-800 border border-gray-700 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20 text-white placeholder-gray-500"
            />
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="px-8 py-4 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg font-semibold hover:from-blue-600 hover:to-purple-700 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed transform hover:scale-105 active:scale-95"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Analyzing...
                </span>
              ) : (
                'Analyze'
              )}
            </button>
          </div>
          {error && (
            <div className="mt-4 p-4 bg-red-900/20 border border-red-500 rounded-lg text-red-400">
              {error}
            </div>
          )}
        </div>

        {/* Results Section */}
        {data && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Geo Info Card */}
              <InfoCard title="Geo Info" data={data.geo}>
                {data.geo && !data.geo.error && (
                  <div className="space-y-2 text-sm">
                    <InfoRow label="Country" value={data.geo.country || 'N/A'} />
                    <InfoRow label="Region" value={data.geo.regionName || 'N/A'} />
                    <InfoRow label="City" value={data.geo.city || 'N/A'} />
                    <InfoRow label="ISP" value={data.geo.isp || 'N/A'} />
                    <InfoRow label="Organization" value={data.geo.org || 'N/A'} />
                    <InfoRow label="ASN" value={data.geo.as || 'N/A'} />
                    <InfoRow label="AS Name" value={data.geo.asname || 'N/A'} />
                    {data.geo.lat && data.geo.lon && (
                      <InfoRow label="Coordinates" value={`${data.geo.lat}, ${data.geo.lon}`} />
                    )}
                  </div>
                )}
              </InfoCard>

              {/* RDAP Info Card */}
              <InfoCard title="RDAP Info" data={data.rdap}>
                {data.rdap && !data.rdap.error && (
                  <div className="space-y-2 text-sm">
                    <InfoRow label="Network" value={data.rdap.name || 'N/A'} />
                    <InfoRow label="Org" value={data.rdap.org || 'N/A'} />
                    <InfoRow label="Type" value={data.rdap.type || 'N/A'} />
                    {data.rdap.country && <InfoRow label="Country" value={data.rdap.country} />}
                    {data.rdap.startAddress && (
                      <InfoRow label="Range" value={`${data.rdap.startAddress} - ${data.rdap.endAddress}`} />
                    )}
                  </div>
                )}
              </InfoCard>

              {/* DNS Info Card */}
              <InfoCard title="DNS Info" data={data.dns}>
                {data.dns && !data.dns.error && data.dns.Answer && (
                  <div className="space-y-2 text-sm">
                    <InfoRow label="Records Found" value={data.dns.Answer.length} />
                    {data.dns.Answer.slice(0, 5).map((answer, idx) => (
                      <InfoRow
                        key={idx}
                        label={`A Record ${idx + 1}`}
                        value={answer.data}
                      />
                    ))}
                  </div>
                )}
              </InfoCard>

              {/* HTTP Info Card */}
              <InfoCard title="HTTP Info" data={data.http}>
                {data.http && !data.http.error && (
                  <div className="space-y-2 text-sm">
                    <InfoRow label="Status" value={data.http.status || 'N/A'} />
                    <InfoRow label="Server" value={data.http.server || 'N/A'} />
                    {data.http.headers && (
                      <>
                        {data.http.headers['content-type'] && (
                          <InfoRow label="Content-Type" value={data.http.headers['content-type']} />
                        )}
                        {data.http.headers['x-powered-by'] && (
                          <InfoRow label="Powered By" value={data.http.headers['x-powered-by']} />
                        )}
                      </>
                    )}
                  </div>
                )}
              </InfoCard>

              {/* AI Threat Assessment Card */}
              <InfoCard title="🤖 AI Threat Assessment" data={data.aiAnalysis}>
                {data.aiAnalysis && !data.aiAnalysis.error && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400 text-sm font-medium">Risk Score:</span>
                      <span className={`text-2xl font-bold ${
                        data.aiAnalysis.riskScore >= 7 ? 'text-red-500' :
                        data.aiAnalysis.riskScore >= 4 ? 'text-orange-500' :
                        'text-green-500'
                      }`}>
                        {data.aiAnalysis.riskScore}/10
                      </span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2.5">
                      <div
                        className={`h-2.5 rounded-full ${
                          data.aiAnalysis.riskScore >= 7 ? 'bg-red-500' :
                          data.aiAnalysis.riskScore >= 4 ? 'bg-orange-500' :
                          'bg-green-500'
                        }`}
                        style={{ width: `${data.aiAnalysis.riskScore * 10}%` }}
                      ></div>
                    </div>
                    <div className="text-xs text-gray-400">
                      Severity: <span className="text-white font-semibold">{data.aiAnalysis.severity}</span>
                    </div>
                    <div className="text-sm text-gray-300 pt-2 border-t border-gray-700">
                      {data.aiAnalysis.summary}
                    </div>
                    {data.aiAnalysis.indicators && data.aiAnalysis.indicators.length > 0 && (
                      <div className="pt-2">
                        <p className="text-xs text-gray-400 mb-1">Key Indicators:</p>
                        <ul className="list-disc list-inside text-xs text-yellow-400 space-y-1">
                          {data.aiAnalysis.indicators.map((indicator, idx) => (
                            <li key={idx}>{indicator}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </InfoCard>

              {/* Historical Abuse Card */}
              {data.abuseipdb && (
                <InfoCard title="Historical Abuse" data={data.abuseipdb}>
                  {!data.abuseipdb.error && data.abuseipdb.data && (
                    <div className="space-y-2 text-sm">
                      <InfoRow label="Abuse Score" value={`${data.abuseipdb.data.abuseConfidenceScore}%`} />
                      <InfoRow label="Reports" value={data.abuseipdb.data.totalReports || '0'} />
                      <InfoRow label="Usage Type" value={data.abuseipdb.data.usageType || 'N/A'} />
                      <InfoRow label="ISP" value={data.abuseipdb.data.isp || 'N/A'} />
                      <InfoRow label="Domain" value={data.abuseipdb.data.domain || 'N/A'} />
                    </div>
                  )}
                  {!data.abuseipdb.error && !data.abuseipdb.data && (
                    <p className="text-gray-400 text-sm">No abuse reports found</p>
                  )}
                </InfoCard>
              )}

              {/* Network Recon Card */}
              {data.ports && (
                <InfoCard title="Network Recon" data={data.ports}>
                  {!data.ports.error && Array.isArray(data.ports) && data.ports.length > 0 ? (
                    <div className="space-y-2 text-sm">
                      <p className="text-gray-400 mb-2">Open Ports:</p>
                      <div className="flex flex-wrap gap-2">
                        {data.ports.map((port, idx) => (
                          <span key={idx} className="px-3 py-1 bg-blue-900/30 text-blue-300 rounded-md text-xs font-mono">
                            {port.port}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p className="text-gray-400 text-sm">No open ports detected</p>
                  )}
                </InfoCard>
              )}

              {/* Subdomain Discovery Card */}
              {data.subdomains && Array.isArray(data.subdomains) && data.subdomains.length > 0 && (
                <InfoCard title="Subdomain Discovery" data={data.subdomains}>
                  <div className="space-y-2 text-sm">
                    <p className="text-gray-400 mb-2">Found {data.subdomains.length} subdomains:</p>
                    <div className="max-h-40 overflow-y-auto space-y-1">
                      {data.subdomains.slice(0, 10).map((subdomain, idx) => (
                        <div key={idx} className="text-xs text-green-400 font-mono bg-gray-900/50 px-2 py-1 rounded">
                          {subdomain}
                        </div>
                      ))}
                      {data.subdomains.length > 10 && (
                        <p className="text-xs text-gray-500">...and {data.subdomains.length - 10} more</p>
                      )}
                    </div>
                  </div>
                </InfoCard>
              )}
            </div>

            {/* Footer */}
            <div className="text-center pt-8 border-t border-gray-700 text-gray-400 text-sm">
              Data sources: ip-api.com, RDAP, Cloudflare DNS, VirusTotal, AbuseIPDB, Certificate Transparency, AI Threat Analysis
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function InfoCard({ title, data, children }) {
  if (!data) return null;

  if (data.error) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 className="text-xl font-semibold mb-4 text-blue-400">{title}</h3>
        <p className="text-red-400 text-sm">{data.error}</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-gray-600 transition-colors">
      <h3 className="text-xl font-semibold mb-4 text-blue-400">{title}</h3>
      {children}
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="flex justify-between items-start py-1 border-b border-gray-700/50">
      <span className="text-gray-400 font-medium">{label}:</span>
      <span className="text-white text-right break-all ml-4">{value}</span>
    </div>
  );
}
