'use client';

interface Process {
  process_name: string;
  pid: number;
  suspicious: boolean;
  vad_count?: number;
  reason?: string;
}

interface AnalysisData {
  volatility: {
    analysis_type: string;
    process_count: number;
    suspicious_count: number;
    processes: Process[];
  };
  ioc: {
    hashes: {
      md5: string;
      sha1: string;
      sha256: string;
    };
    ioc_matches: any[];
    file_size: number;
  };
  riskScore: number;
}

interface AnalysisResultsProps {
  data: AnalysisData;
}

export default function AnalysisResults({ data }: AnalysisResultsProps) {
  if (!data) return null;

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6">Analysis Results</h2>
      
      {/* Risk Score */}
      <div className="mb-8">
        <h3 className="text-lg font-semibold mb-4">Risk Assessment</h3>
        <div className="w-full bg-gray-200 rounded-full h-4">
          <div 
            className="bg-red-600 h-4 rounded-full transition-all duration-500"
            style={{ width: `${data.riskScore}%` }}
          ></div>
        </div>
        <p className="mt-2 text-sm text-gray-600">
          Risk Score: {data.riskScore}/100 - {
            data.riskScore > 75 ? 'High Risk' : 
            data.riskScore > 50 ? 'Medium Risk' : 'Low Risk'
          }
        </p>
      </div>

      {/* Process Analysis */}
      <div className="mb-8">
        <h3 className="text-lg font-semibold mb-4">Process Analysis</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div className="bg-blue-50 p-4 rounded-lg">
            <p className="text-2xl font-bold text-blue-700">{data.volatility.process_count}</p>
            <p className="text-sm text-blue-600">Total Processes</p>
          </div>
          <div className="bg-red-50 p-4 rounded-lg">
            <p className="text-2xl font-bold text-red-700">{data.volatility.suspicious_count}</p>
            <p className="text-sm text-red-600">Suspicious Processes</p>
          </div>
          <div className="bg-green-50 p-4 rounded-lg">
            <p className="text-2xl font-bold text-green-700">{data.volatility.process_count - data.volatility.suspicious_count}</p>
            <p className="text-sm text-green-600">Clean Processes</p>
          </div>
        </div>

        {/* Process List */}
        {data.volatility.processes.length > 0 && (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Process</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">PID</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {data.volatility.processes.map((process, index) => (
                  <tr key={index}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {process.process_name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {process.pid}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        process.suspicious 
                          ? 'bg-red-100 text-red-800' 
                          : 'bg-green-100 text-green-800'
                      }`}>
                        {process.suspicious ? 'Suspicious' : 'Clean'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* IOC Results */}
      <div>
        <h3 className="text-lg font-semibold mb-4">IOC Analysis</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div className="bg-gray-50 p-4 rounded-lg">
            <p className="text-sm font-medium text-gray-600">MD5</p>
            <p className="text-xs font-mono text-gray-500 truncate">{data.ioc.hashes.md5}</p>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg">
            <p className="text-sm font-medium text-gray-600">SHA1</p>
            <p className="text-xs font-mono text-gray-500 truncate">{data.ioc.hashes.sha1}</p>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg">
            <p className="text-sm font-medium text-gray-600">SHA256</p>
            <p className="text-xs font-mono text-gray-500 truncate">{data.ioc.hashes.sha256}</p>
          </div>
        </div>

        {data.ioc.ioc_matches.length > 0 ? (
          <div className="bg-red-50 p-4 rounded-lg">
            <h4 className="font-semibold text-red-800 mb-2">IOC Matches Found</h4>
            <ul className="list-disc list-inside text-sm text-red-600">
              {data.ioc.ioc_matches.map((match, index) => (
                <li key={index}>{match.value} - {match.source} ({match.severity})</li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="bg-green-50 p-4 rounded-lg">
            <p className="text-green-800">No known IOCs detected</p>
          </div>
        )}
      </div>
    </div>
  );
}