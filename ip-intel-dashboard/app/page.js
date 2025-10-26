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
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="container mx-auto px-4 py-12 max-w-7xl">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 mb-4">
            <div className="w-10 h-10 bg-cyan-500 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <h1 className="text-5xl font-bold text-white">
              IP Intelligence
            </h1>
          </div>
          <p className="text-slate-400 text-lg">
            Advanced threat analysis and network reconnaissance
          </p>
        </div>

        {/* Input Section */}
        <div className="max-w-2xl mx-auto mb-12">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Enter IP or domain (8.8.8.8, example.com)"
                className="w-full pl-12 pr-4 py-4 rounded-xl bg-slate-900 border border-slate-800 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 text-white placeholder-slate-500 transition-colors"
              />
            </div>
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="px-8 py-4 bg-cyan-600 rounded-xl font-medium hover:bg-cyan-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed active:scale-[0.98]"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Analyzing
                </span>
              ) : (
                'Analyze'
              )}
            </button>
          </div>
          {error && (
            <div className="mt-4 p-4 bg-red-950/50 border border-red-900 rounded-xl text-red-300">
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
              <InfoCard title="AI Threat Assessment" data={data.aiAnalysis}>
                {data.aiAnalysis && !data.aiAnalysis.error && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-sm font-medium">Risk Score</span>
                      <span className={`text-3xl font-bold ${
                        data.aiAnalysis.riskScore >= 7 ? 'text-red-400' :
                        data.aiAnalysis.riskScore >= 4 ? 'text-orange-400' :
                        'text-emerald-400'
                      }`}>
                        {data.aiAnalysis.riskScore}/10
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full transition-all ${
                          data.aiAnalysis.riskScore >= 7 ? 'bg-red-400' :
                          data.aiAnalysis.riskScore >= 4 ? 'bg-orange-400' :
                          'bg-emerald-400'
                        }`}
                        style={{ width: `${data.aiAnalysis.riskScore * 10}%` }}
                      ></div>
                    </div>
                    <div className="text-xs text-slate-400">
                      Severity: <span className="text-white font-semibold">{data.aiAnalysis.severity}</span>
                    </div>
                    <div className="text-sm text-slate-300 pt-3 border-t border-slate-800">
                      {data.aiAnalysis.summary}
                    </div>
                    {data.aiAnalysis.indicators && data.aiAnalysis.indicators.length > 0 && (
                      <div className="pt-3 border-t border-slate-800">
                        <p className="text-xs text-slate-400 mb-2 font-medium">Key Indicators</p>
                        <ul className="space-y-1.5">
                          {data.aiAnalysis.indicators.map((indicator, idx) => (
                            <li key={idx} className="text-xs text-amber-400 flex items-start gap-2">
                              <span className="text-amber-500 mt-0.5">•</span>
                              <span>{indicator}</span>
                            </li>
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
                <InfoCard title="Network Reconnaissance" data={data.ports}>
                  {!data.ports.error && Array.isArray(data.ports) && data.ports.length > 0 ? (
                    <div className="space-y-2 text-sm">
                      <p className="text-slate-400 mb-3 text-xs font-medium uppercase tracking-wider">Open Ports</p>
                      <div className="flex flex-wrap gap-2">
                        {data.ports.map((port, idx) => (
                          <span key={idx} className="px-3 py-1.5 bg-cyan-950/50 text-cyan-300 border border-cyan-800/50 rounded-lg text-xs font-mono">
                            {port.port}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p className="text-slate-400 text-sm">No open ports detected</p>
                  )}
                </InfoCard>
              )}

              {/* Subdomain Discovery Card */}
              {data.subdomains && Array.isArray(data.subdomains) && data.subdomains.length > 0 && (
                <InfoCard title="Subdomain Discovery" data={data.subdomains}>
                  <div className="space-y-2 text-sm">
                    <p className="text-slate-400 mb-3 text-xs font-medium uppercase tracking-wider">Found {data.subdomains.length} subdomains</p>
                    <div className="max-h-40 overflow-y-auto space-y-1.5 scrollbar-thin scrollbar-thumb-slate-700">
                      {data.subdomains.slice(0, 10).map((subdomain, idx) => (
                        <div key={idx} className="text-xs text-emerald-400 font-mono bg-emerald-950/20 border border-emerald-900/50 px-3 py-1.5 rounded-lg">
                          {subdomain}
                        </div>
                      ))}
                      {data.subdomains.length > 10 && (
                        <p className="text-xs text-slate-500 pt-1">...and {data.subdomains.length - 10} more</p>
                      )}
                    </div>
                  </div>
                </InfoCard>
              )}
            </div>

            {/* Footer */}
            <div className="text-center pt-8 border-t border-slate-800 text-slate-500 text-xs">
              Data sources: ip-api.com • RDAP • Cloudflare DNS • VirusTotal • AbuseIPDB • Certificate Transparency
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
      <div className="bg-slate-900/50 rounded-xl p-6 border border-slate-800 backdrop-blur-sm">
        <h3 className="text-lg font-semibold mb-4 text-white">{title}</h3>
        <p className="text-red-300 text-sm">{data.error}</p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/50 rounded-xl p-6 border border-slate-800 hover:border-slate-700 transition-colors backdrop-blur-sm">
      <h3 className="text-lg font-semibold mb-4 text-white">{title}</h3>
      {children}
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="flex justify-between items-start py-1.5 border-b border-slate-800/50">
      <span className="text-slate-400 font-medium text-sm">{label}</span>
      <span className="text-white text-right break-all ml-4 text-sm">{value}</span>
    </div>
  );
}
