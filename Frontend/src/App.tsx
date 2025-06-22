import React, { useState, useEffect, useRef } from "react";
import { Shield, Bot, Server, HdmiPort, Lock, Globe, Network, ChevronDown, FileText, ChevronUp, Loader2 } from "lucide-react";
import { toast } from 'react-toastify';

function App() {
  const [url, setUrl] = useState("");
  const [scannedUrl, setScannedUrl] = useState("");
  const [isUrlFilled, setIsUrlFilled] = useState(true);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState<typeof mockScanResults.reconnaissance | null>(null);

  const [expandedSections, setExpandedSections] = useState({
    serverInfo: true,
    openPorts: true,
    dnsRecords: true,
    subdomains: true,
    securityHeaders: true,
    robotsTxt: true,
    whois: true,
    ssl: true
  });

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections({
      ...expandedSections,
      [section]: !expandedSections[section],
    });
  };

  const mockScanResults = {
    reconnaissance: {
      serverInfo: {
        ip: "Unknown",
        OS: "Unknown",
        webServerType: "Unknown",
        cms: "Unknown",
        hostingProvider: "Unknown"
      },
      openPorts: [
        { port: "-", service: "-", status: "-"},
      ],
      dnsRecords: [
        { type: "-", data: "-" },
      ],
  
      subdomains: ["-"],
  
      securityHeaders: [
        { name: "Content-Security-Policy", present: false, risk: "high" },
        { name: "X-XSS-Protection", present: true, risk: "low" },
        { name: "X-Frame-Options", present: true, risk: "low" },
        { name: "Strict-Transport-Security", present: false, risk: "medium" },
      ],
  
      robotsTxt: "",
  
      "whois": {
        "domain": "example.com",
        "registrar": "NameCheap, Inc.",
        "creationDate": "2010-06-15",
        "expiryDate": "2030-06-15",
        "nameServers": ["ns1.example.com", "ns2.example.com"]
      },
      
      "ssl": {
        "issuer": "Let's Encrypt Authority X3",
        "validFrom": "2024-04-10",
        "validTo": "2024-07-09",
        "protocol": "TLS 1.3",
        "keySize": "2048 bits",
        "status": "Valid"
      }
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
  
    if (url.trim() === "") {
      setIsUrlFilled(false);
      return;
    }
  
    if (!isValidUrl(url)) {
      setIsUrlFilled(false);
      return;
    }
  
    setIsUrlFilled(true);

    (termsAccepted) ? handleScan() : setIsModalOpen(true);
  };
  
  const isValidUrl = (string:string) => {
    const pattern = new RegExp('^(https?:\\/\\/)?' + // protocol (optional)
      '((([a-z\\d]([a-z\\d-]*[a-z\\d])*).)+[a-z]{2,}|' + // domain name
      '((\\d{1,3}\\.){3}\\d{1,3}))' + // OR IPv4 address
      '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + // port and path (optional)
      '(\\?[;&a-z\\d%_.~+=-]*)?' + // query string (optional)
      '(\\#[-a-z\\d_]*)?$', 'i'); // fragment locator (optional)
  
    return pattern.test(string);
  };
  

  const handleScan = async () => {
    setScannedUrl(url);

    setIsModalOpen(false);

    setScanResults(mockScanResults.reconnaissance);
    return;
    setIsScanning(true);

    const backendUrl = import.meta.env.VITE_BACKEND_URL;

    try {
      const res = await fetch(`${backendUrl}/api/recon`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data ? data.error : `HTTP error! Status: ${res.status}`);
      }

      setScanResults(data);

      setIsScanning(false);
    } catch (err: unknown) {
      setScanResults(null);
      
      if (err instanceof Error) {
        toast.error(err.message);
      } else {
        toast.error('An unexpected error occurred.');
      }

      setIsScanning(false);
    }
  };

  const ws = useRef<WebSocket | null>(null);
  const [xssLogs, setXssLogs] = useState<string[]>([]);
  const [sqlLogs, setSqlLogs] = useState<string[]>([]);
  const [isXsstrikeLoading, setIsXsstrikeLoading] = useState<boolean>(false);
  const [isSqlmapLoading, setIsSqlmapLoading] = useState<boolean>(false);

  useEffect(() => {
    ws.current = new WebSocket("ws://localhost:8000/ws/ping");

    ws.current.onmessage = (event: MessageEvent) => {
      const data = event.data as string;
      if (data.startsWith("xss:")) {
        setXssLogs((prevLogs) => [...prevLogs, data.replace(/^xss:/, "")]);
      } else if (data.startsWith("sql:")) {
        setSqlLogs((prevLogs) => [...prevLogs, data.replace(/^sql:/, "")]);
      } else {
        // fallback: append to both logs if not prefixed
        setXssLogs((prevLogs) => [...prevLogs, data]);
        setSqlLogs((prevLogs) => [...prevLogs, data]);
      }
    };

    ws.current.onclose = () => {
      setXssLogs((prevLogs) => [...prevLogs, "Connection closed."]);
      setSqlLogs((prevLogs) => [...prevLogs, "Connection closed."]);
    };

    ws.current.onerror = () => {
      setXssLogs((prevLogs) => [...prevLogs, "WebSocket error."]);
      setSqlLogs((prevLogs) => [...prevLogs, "WebSocket error."]);
    };

    return () => {
      ws.current?.close();
    };
  }, []);

  const startXss = () => {
    if (!ws.current || ws.current.readyState !== WebSocket.OPEN) {
      setXssLogs(["WebSocket not connected."]);
      return;
    }
    setIsXsstrikeLoading(true);
    setXssLogs([]);
    ws.current.send(`xss:${url}`);
    // Stop loading when scan completed message is received
    const stopLoading = (event: MessageEvent) => {
      if (event.data.startsWith("xss:XSStrike scan completed.")) {
        setIsXsstrikeLoading(false);
        ws.current?.removeEventListener('message', stopLoading);
      }
    };
    ws.current.addEventListener('message', stopLoading);
  };

  const startSql = () => {
    if (!ws.current || ws.current.readyState !== WebSocket.OPEN) {
      setSqlLogs(["WebSocket not connected."]);
      return;
    }
    setIsSqlmapLoading(true);
    setSqlLogs([]);
    ws.current.send(`sql:${url}`);
    // Stop loading when scan completed message is received
    const stopLoading = (event: MessageEvent) => {
      if (event.data.startsWith("sql:sqlmap scan completed.")) {
        setIsSqlmapLoading(false);
        ws.current?.removeEventListener('message', stopLoading);
      }
    };
    ws.current.addEventListener('message', stopLoading);
  };

  return (
    <div className="min-h-screen bg-gray-50 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')]">
      <header className="bg-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8 flex items-center justify-between">
          <div className="flex items-center">
            <Shield className="h-8 w-8 text-indigo-600 mr-3" />
            <h1 className="text-2xl font-bold text-gray-900">
              SecureScan
            </h1>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        <div className="bg-white rounded-lg shadow-lg p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">
            Scan a Website for Vulnerabilities
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="url"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Website URL
              </label>
              <div className="flex">
                <input
                  id="url"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => {setUrl(e.target.value); setIsUrlFilled(true);}}
                  className="flex-1 min-w-0 block w-full px-3 py-2 rounded-l-md border border-gray-300 shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  style={{ borderColor: isUrlFilled ? "gray" : "red", borderWidth: isUrlFilled ? "1px" : "2px"}}
                />
                <button
                  type="submit"
                  className="inline-flex items-center px-4 py-2 border border-transparent rounded-r-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  Scan Now
                </button>
              </div>
            </div>
          </form>
        </div>

        {isScanning && (
          <div className="bg-white rounded-lg shadow-lg p-8 mb-8 flex flex-col items-center justify-center">
            <Loader2 className="h-12 w-12 text-indigo-600 animate-spin mb-4" />
            <h2 className="text-xl font-semibold mb-2">Scanning in Progress</h2>
            <p className="text-gray-600 text-center max-w-md">
              We're scanning <b>{url}</b> for active reconnaissance data. This may take a few moments...
            </p>
          </div>
        )}

        {scanResults && !isScanning && (
          <div className="space-y-8">
            <div className="bg-white rounded-lg shadow-lg overflow-hidden">
              <div className="bg-indigo-700 px-6 py-4">
                <h2 className="text-xl font-bold text-white">
                  Scan Results for {scannedUrl}
                </h2>
              </div>

              <div className="p-6">
                <div className="mb-8">
                  <h3 className="text-lg font-semibold mb-4">
                    Reconnaissance Details
                  </h3>

                  {/* Server Information */}
                  <div className="mb-4 border rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
                      onClick={() => toggleSection("serverInfo")}
                    >
                      <div className="flex items-center">
                        <Server className="h-5 w-5 text-indigo-600 mr-2" />
                        <span className="font-medium">Server Information</span>
                      </div>
                      {expandedSections.serverInfo ? (
                        <ChevronUp className="h-5 w-5" />
                      ) : (
                        <ChevronDown className="h-5 w-5" />
                      )}
                    </button>

                    {expandedSections.serverInfo && (
                      <div className="p-4 border-t">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="bg-gray-50 p-3 rounded">
                            <p className="text-sm text-gray-500">IP Address</p>
                            <p className="font-medium">
                              {scanResults.serverInfo.ip}
                            </p>
                          </div>
                          <div className="bg-gray-50 p-3 rounded">
                            <p className="text-sm text-gray-500">
                              Operating System
                            </p>
                            <p className="font-medium">
                              {scanResults.serverInfo.OS}
                            </p>
                          </div>
                          <div className="bg-gray-50 p-3 rounded">
                            <p className="text-sm text-gray-500">Web Server</p>
                            <p className="font-medium">
                              {
                                scanResults.serverInfo
                                  .webServerType
                              }
                            </p>
                          </div>
                          <div className="bg-gray-50 p-3 rounded">
                            <p className="text-sm text-gray-500">CMS</p>
                            <p className="font-medium">
                              {scanResults.serverInfo.cms}
                            </p>
                          </div>
                          <div className="bg-gray-50 p-3 rounded">
                            <p className="text-sm text-gray-500">Hosting Provider</p>
                            <p className="font-medium">
                              {scanResults.serverInfo.hostingProvider}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Open Ports & Services */}
                  <div className="mb-4 border rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
                      onClick={() => toggleSection("openPorts")}
                    >
                      <div className="flex items-center">
                        <HdmiPort className="h-5 w-5 text-indigo-600 mr-2" />
                        <span className="font-medium">
                          Open Ports & Services
                        </span>
                      </div>
                      {expandedSections.openPorts ? (
                        <ChevronUp className="h-5 w-5" />
                      ) : (
                        <ChevronDown className="h-5 w-5" />
                      )}
                    </button>

                    {expandedSections.openPorts && (
                      <div className="p-4 border-t">
                        <div className="overflow-x-auto">
                          <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                              <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                  Port
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                  Service
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                  Status
                                </th>
                              </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                              {scanResults.openPorts.map(
                                (port, index) => (
                                  <tr key={index}>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                      {port.port}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                      {port.service}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                      {port.status}
                                    </td>
                                  </tr>
                                )
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* DNS records */}
                  <div className="mb-4 border rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
                      onClick={() => toggleSection("dnsRecords")}
                    >
                      <div className="flex items-center">
                        <Globe className="h-5 w-5 text-indigo-600 mr-2" />
                        <span className="font-medium">DNS Records</span>
                      </div>
                      {expandedSections.dnsRecords ? (
                        <ChevronUp className="h-5 w-5" />
                      ) : (
                        <ChevronDown className="h-5 w-5" />
                      )}
                    </button>

                    {expandedSections.dnsRecords && (
                      <div className="p-4 border-t">
                        <div className="overflow-x-auto">
                          <table className="min-w-full divide-y divide-gray-200 shadow-sm border rounded-md">
                            <thead className="bg-gray-50">
                              <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                  Type
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                  Data
                                </th>
                              </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                              {scanResults.dnsRecords.map(
                                (record, index) => (
                                  <tr key={index} className="hover:bg-gray-50">
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                      {record.type || "—"}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                                      {record.data || "—"}
                                    </td>
                                  </tr>
                                )
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Subdomains */}
                  <div className="mb-4 border rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
                      onClick={() => toggleSection("subdomains")}
                    >
                      <div className="flex items-center">
                        <Network className="h-5 w-5 text-indigo-600 mr-2" />
                        <span className="font-medium">Subdomains</span>
                      </div>
                      {expandedSections.subdomains ? (
                        <ChevronUp className="h-5 w-5" />
                      ) : (
                        <ChevronDown className="h-5 w-5" />
                      )}
                    </button>

                    {expandedSections.subdomains && (
                      <div className="p-4 border-t">
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                          {scanResults.subdomains.map(
                            (subdomain, index) => (
                              <div
                                key={index}
                                className="bg-gray-50 p-2 rounded text-sm"
                              >
                                {subdomain}
                              </div>
                            )
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Security Headers Analysis */}
                  <div className="mb-4 border rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
                      onClick={() => toggleSection("securityHeaders")}
                    >
                      <div className="flex items-center">
                        <Shield className="h-5 w-5 text-indigo-600 mr-2" />
                        <span className="font-medium">
                          Security Headers Analysis
                        </span>
                      </div>
                      {expandedSections.securityHeaders ? (
                        <ChevronUp className="h-5 w-5" />
                      ) : (
                        <ChevronDown className="h-5 w-5" />
                      )}
                    </button>

                    {expandedSections.securityHeaders && (
                      <div className="p-4 border-t">
                        <div className="overflow-x-auto">
                          <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                              <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                  Header
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                  Status
                                </th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                  Risk
                                </th>
                              </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                              {scanResults.securityHeaders.map(
                                (header, index) => (
                                  <tr key={index}>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                      {header.name}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                      {header.present ? (
                                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                          Present
                                        </span>
                                      ) : (
                                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                          Missing
                                        </span>
                                      )}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                      <span
                                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize ${
                                          header.risk === "low"
                                            ? "bg-green-100 text-green-800"
                                            : header.risk === "medium"
                                            ? "bg-orange-100 text-orange-800"
                                            : "bg-red-100 text-red-800"
                                        }`}
                                      >
                                        {header.risk}
                                      </span>
                                    </td>
                                  </tr>
                                )
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* robots.txt Display */}
                  <div className="mb-4 border rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
                      onClick={() => toggleSection("robotsTxt")}
                    >
                      <div className="flex items-center">
                        <Bot className="h-5 w-5 text-indigo-600 mr-2" />
                        <span className="font-medium">robots.txt</span>
                      </div>
                      {expandedSections.robotsTxt ? (
                        <ChevronUp className="h-5 w-5" />
                      ) : (
                        <ChevronDown className="h-5 w-5" />
                      )}
                    </button>

                    {expandedSections.robotsTxt && (
                      <div className="p-4 border-t bg-gray-50">
                        <pre className="bg-black text-green-400 p-4 rounded-md overflow-x-auto text-sm leading-relaxed font-mono whitespace-pre-wrap">
                          {scanResults.robotsTxt?.trim()
                            ? scanResults.robotsTxt
                            : "No robots.txt found or it is empty."}
                        </pre>
                      </div>
                    )}
                  </div>
                  {/* WHOIS Information */}
                  <div className="mb-4 border rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
                      onClick={() => toggleSection("whois")}
                    >
                      <div className="flex items-center">
                        <FileText className="h-5 w-5 text-indigo-600 mr-2" />
                        <span className="font-medium">WHOIS Information</span>
                      </div>
                      {expandedSections.whois ? (
                        <ChevronUp className="h-5 w-5" />
                      ) : (
                        <ChevronDown className="h-5 w-5" />
                      )}
                    </button>

                    {expandedSections.whois && (
                      <div className="p-4 border-t bg-white text-sm space-y-2">
                        <p>
                          <strong>Domain:</strong>{" "}
                          {scanResults.whois.domain || "N/A"}
                        </p>
                        <p>
                          <strong>Registrar:</strong>{" "}
                          {scanResults.whois.registrar || "N/A"}
                        </p>
                        <p>
                          <strong>Created:</strong>{" "}
                          {scanResults.whois.creationDate ||
                            "N/A"}
                        </p>
                        <p>
                          <strong>Expires:</strong>{" "}
                          {scanResults.whois.expiryDate || "N/A"}
                        </p>
                        <p>
                          <strong>Name Servers:</strong>{" "}
                          {scanResults.whois.nameServers?.join(
                            ", "
                          ) || "N/A"}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* SSL/TLS Information */}
                  <div className="mb-4 border rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 transition-colors"
                      onClick={() => toggleSection("ssl")}
                    >
                      <div className="flex items-center">
                        <Lock className="h-5 w-5 text-indigo-600 mr-2" />
                        <span className="font-medium">
                          SSL/TLS Reconnaissance
                        </span>
                      </div>
                      {expandedSections.ssl ? (
                        <ChevronUp className="h-5 w-5" />
                      ) : (
                        <ChevronDown className="h-5 w-5" />
                      )}
                    </button>

                    {expandedSections.ssl && (
                      <div className="p-4 border-t bg-white text-sm space-y-2">
                        <p>
                          <strong>Issuer:</strong>{" "}
                          {scanResults.ssl.issuer || "N/A"}
                        </p>
                        <p>
                          <strong>Valid From:</strong>{" "}
                          {scanResults.ssl.validFrom || "N/A"}
                        </p>
                        <p>
                          <strong>Valid To:</strong>{" "}
                          {scanResults.ssl.validTo || "N/A"}
                        </p>
                        <p>
                          <strong>Protocol:</strong>{" "}
                          {scanResults.ssl.protocol || "N/A"}
                        </p>
                        <p>
                          <strong>Key Size:</strong>{" "}
                          {scanResults.ssl.keySize || "N/A"}
                        </p>
                        <p>
                          <strong>Certificate Status:</strong>{" "}
                          {scanResults.ssl.status || "N/A"}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
                <div className="mt-8">
                  <h3 className="text-lg font-semibold mb-4 flex items-center">
                    <span className="mr-2">XSS Vulnerability Scan</span>
                  </h3>
                  <button
                    className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:bg-indigo-300 disabled:cursor-not-allowed mb-4"
                    onClick={startXss}
                    disabled={isXsstrikeLoading}
                  >
                    {isXsstrikeLoading ? 'Scanning with XSStrike...' : 'Run XSStrike XSS Scan'}
                  </button>
                  <div className="bg-gray-100 p-4 rounded shadow h-96 overflow-auto">
                    {xssLogs.map((log, index) => (
                      <div key={index} className="text-sm">{log}</div>
                    ))}
                  </div>
                </div>
                <div className="mt-8">
                  <h3 className="text-lg font-semibold mb-4 flex items-center">
                    <span className="mr-2">SQL Injection Vulnerability Scan</span>
                  </h3>
                  <button
                    className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:bg-indigo-300 disabled:cursor-not-allowed mb-4"
                    onClick={startSql}
                    disabled={isSqlmapLoading}
                  >
                    {isSqlmapLoading ? 'Scanning with sqlmap...' : 'Run SQL Injection Scan'}
                  </button>
                  <div className="bg-gray-100 p-4 rounded shadow h-96 overflow-auto">
                    {sqlLogs.map((log, index) => (
                      <div key={index} className="text-sm">{log}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Terms & Conditions Modal */}
        {isModalOpen && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg max-w-md w-full p-6 max-h-[90vh] overflow-y-auto">
              <h3 className="text-lg font-semibold mb-4">Terms & Conditions</h3>
              <div className="prose prose-sm mb-4 text-gray-600">
                <p>
                  By using this security scanning service, you agree to the
                  following terms:
                </p>
                <ol className="list-decimal pl-5 space-y-2">
                  <li>
                    You confirm that you have authorization to scan the target
                    website.
                  </li>
                  <li>
                    You understand that unauthorized scanning of websites may be
                    illegal in some jurisdictions.
                  </li>
                  <li>
                    The scan results are provided for informational purposes
                    only and do not guarantee complete security assessment.
                  </li>
                  <li>
                    We are not responsible for any damages that may occur as a
                    result of using this service.
                  </li>
                  <li>
                    You will not use this tool for malicious purposes or to
                    exploit vulnerabilities discovered.
                  </li>
                </ol>
              </div>
              <div className="flex items-center mb-4">
                <input
                  type="checkbox"
                  id="accept-terms"
                  checked={termsAccepted}
                  onChange={() => setTermsAccepted(!termsAccepted)}
                  className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                />
                <label
                  htmlFor="accept-terms"
                  className="ml-2 block text-sm text-gray-900"
                >
                  I accept the Terms & Conditions
                </label>
              </div>
              <div className="flex justify-end space-x-3">
                <button
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  Cancel
                </button>
                <button
                  onClick={handleScan}
                  disabled={!termsAccepted}
                  className={`px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white ${
                    termsAccepted
                      ? "bg-indigo-600 hover:bg-indigo-700"
                      : "bg-indigo-300 cursor-not-allowed"
                  } focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500`}
                >
                  Proceed with Scan
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="bg-white border-t mt-12">
        <div className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
          <p className="text-sm text-gray-500 text-center">
            SecureScan &copy; 2025. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
