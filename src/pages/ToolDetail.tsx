
import React from "react";
import { useParams, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { ArrowLeft, ExternalLink, Download, Github } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const ToolDetail = () => {
  const { toolId } = useParams();
  const { toast } = useToast();
  
  // Tool data - this would ideally come from a database or API
  const securityTools = [
    {
      id: 1,
      name: "Log Analyzer",
      description: "Analyzes authentication logs to detect suspicious login attempts and potential brute force attacks.",
      longDescription: "This Python script parses system authentication logs to identify patterns of failed login attempts that could indicate brute force attacks. It searches for multiple failed attempts from the same IP address within a short timeframe and generates alerts with detailed information about the potential attack.",
      usage: "python log_analyzer.py --log-file [path-to-logfile] --threshold [threshold]",
      requirements: ["Python 3.6+", "pandas", "matplotlib (for visualizations)"],
      example: "python log_analyzer.py --log-file /var/log/auth.log --threshold 5",
      windowsNote: "On Windows, use Security event logs exported from Event Viewer.",
      script: "log_analyzer.py"
    },
    {
      id: 2,
      name: "Port Scanner",
      description: "Performs TCP port scanning on target hosts to identify open ports and running services.",
      longDescription: "A multi-threaded port scanner that can quickly identify open TCP ports on a target system. It uses socket connections to determine if ports are open, closed, or filtered, helping security professionals identify potential entry points into a system.",
      usage: "python port_scanner.py --target [target_host] --ports [port_range] --threads [threads]",
      requirements: ["Python 3.6+", "socket", "threading"],
      example: "python port_scanner.py --target 192.168.1.1 --ports 1-1024 --threads 50",
      windowsNote: "On Windows, run Command Prompt as Administrator for full functionality.",
      script: "port_scanner.py"
    },
    {
      id: 3,
      name: "Password Checker",
      description: "Evaluates password strength based on length, complexity, and common password lists.",
      longDescription: "This tool evaluates the strength of passwords by checking length, character diversity (uppercase, lowercase, numbers, special characters), and comparing against databases of commonly used and previously breached passwords to ensure strong password policies.",
      usage: "python password_checker.py --password [password]",
      requirements: ["Python 3.6+", "requests", "hashlib"],
      example: "python password_checker.py --password MySecureP@ssw0rd",
      script: "password_checker.py"
    },
    {
      id: 4,
      name: "Directory Bruteforce",
      description: "Attempts to discover hidden directories and files on web servers through brute force.",
      longDescription: "A web directory discovery tool that attempts to find hidden directories and files on web servers by systematically checking for the existence of common directory and file names. Useful for identifying potentially vulnerable or unprotected areas of a website.",
      usage: "python directory_bruteforce.py --url [url] --wordlist [wordlist]",
      requirements: ["Python 3.6+", "requests", "argparse"],
      example: "python directory_bruteforce.py --url https://example.com --wordlist wordlists/common.txt",
      script: "directory_bruteforce.py"
    },
    {
      id: 5,
      name: "Packet Sniffer",
      description: "Captures and analyzes network packets to monitor network traffic.",
      longDescription: "A network packet capture tool that intercepts and logs traffic passing over a network. It can capture and decode various protocol information from packets, helping security professionals monitor network activity and troubleshoot network issues.",
      usage: "python packet_sniffer.py --interface [interface] --filter [filter]",
      requirements: ["Python 3.6+", "scapy", "administrator privileges"],
      example: "python packet_sniffer.py --interface eth0 --filter \"tcp port 80\"",
      windowsNote: "On Windows, run Command Prompt as Administrator before using this tool.",
      script: "packet_sniffer.py"
    },
    {
      id: 6,
      name: "File Integrity Monitor",
      description: "Monitors changes to critical files by checking file hashes at regular intervals.",
      longDescription: "This script monitors the integrity of important files by computing and storing cryptographic hashes. It periodically rechecks these files and alerts when changes are detected, helping to identify unauthorized modifications to critical system or application files.",
      usage: "python file_integrity_monitor.py [directory] [interval]",
      requirements: ["Python 3.6+", "hashlib", "schedule"],
      example: "python file_integrity_monitor.py /etc/important-configs/ 60",
      windowsNote: "On Windows, use backward slashes: python file_integrity_monitor.py C:\\important-configs\\ 60",
      script: "file_integrity_monitor.py"
    },
    {
      id: 7,
      name: "Subdomain Enumeration",
      description: "Enumerates subdomains of a target domain using various techniques.",
      longDescription: "A tool for discovering subdomains associated with a target domain using techniques like DNS brute forcing, certificate transparency logs, and search engine results. Helps security researchers map out the attack surface of an organization.",
      usage: "python subdomain_enum.py [domain]",
      requirements: ["Python 3.6+", "requests", "dnspython"],
      example: "python subdomain_enum.py example.com",
      script: "subdomain_enum.py"
    },
    {
      id: 8,
      name: "Web Vulnerability Scanner",
      description: "Scans websites for common vulnerabilities like XSS, SQLi, and open redirects.",
      longDescription: "A basic web vulnerability scanner that checks for common security issues such as XSS (Cross-Site Scripting), SQL injection, open redirects, and misconfigurations. It helps identify potential security weaknesses in web applications.",
      usage: "python web_vuln_scanner.py [url]",
      requirements: ["Python 3.6+", "requests", "beautifulsoup4"],
      example: "python web_vuln_scanner.py https://example.com",
      script: "web_vuln_scanner.py"
    },
    {
      id: 9,
      name: "DNS Reconnaissance",
      description: "Gathers DNS information about domains and IP addresses.",
      longDescription: "This tool performs comprehensive DNS reconnaissance, querying various record types (A, AAAA, MX, TXT, NS, etc.) to gather information about domains. It helps in mapping network infrastructure and identifying potential misconfigurations.",
      usage: "python dns_recon.py [domain]",
      requirements: ["Python 3.6+", "dnspython"],
      example: "python dns_recon.py example.com",
      script: "dns_recon.py"
    },
    {
      id: 10,
      name: "Hash Cracker",
      description: "Attempts to crack password hashes using dictionary and brute force methods.",
      longDescription: "A tool designed to recover passwords from their hash values using dictionary attacks or brute force methods. Supports multiple hash algorithms including MD5, SHA-1, SHA-256, and others. Useful for password recovery or for testing password security.",
      usage: "python hash_cracker.py [hash] [hash_type] [wordlist]",
      requirements: ["Python 3.6+", "hashlib"],
      example: "python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 md5 wordlist.txt",
      script: "hash_cracker.py"
    }
  ];

  const tool = securityTools.find(tool => tool.id === parseInt(toolId || "0"));

  if (!tool) {
    return (
      <div className="min-h-screen bg-gray-50 py-10 px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mx-auto">
          <div className="mb-8">
            <Button variant="outline" asChild>
              <Link to="/" className="flex items-center gap-2">
                <ArrowLeft className="h-4 w-4" /> Back to Tools
              </Link>
            </Button>
          </div>
          <div className="text-center py-20">
            <h1 className="text-3xl font-bold text-gray-900">Tool Not Found</h1>
            <p className="mt-4 text-gray-600">The requested security tool could not be found.</p>
          </div>
        </div>
      </div>
    );
  }

  const handleDownload = () => {
    // In a real app, this would download the script
    toast({
      title: "Download started",
      description: `${tool.script} is downloading...`,
    });
    console.log(`Downloading ${tool.script}`);
  };

  return (
    <div className="min-h-screen bg-gray-50 py-10 px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <Button variant="outline" asChild>
            <Link to="/" className="flex items-center gap-2">
              <ArrowLeft className="h-4 w-4" /> Back to Tools
            </Link>
          </Button>
        </div>

        <div className="bg-white rounded-lg shadow-lg overflow-hidden">
          <div className="p-6 border-b">
            <h1 className="text-3xl font-bold text-gray-900">{tool.name}</h1>
            <p className="mt-2 text-gray-600">{tool.description}</p>
          </div>

          <div className="p-6 border-b">
            <h2 className="text-xl font-semibold mb-4">Description</h2>
            <p className="text-gray-700">{tool.longDescription}</p>
          </div>

          <div className="p-6 border-b">
            <h2 className="text-xl font-semibold mb-4">Usage</h2>
            <div className="bg-gray-100 p-3 rounded-md font-mono text-sm">
              {tool.usage}
            </div>
            <h3 className="text-lg font-medium mt-4 mb-2">Example</h3>
            <div className="bg-gray-100 p-3 rounded-md font-mono text-sm">
              {tool.example}
            </div>
            {tool.windowsNote && (
              <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md text-yellow-800">
                <strong>Note for Windows users:</strong> {tool.windowsNote}
              </div>
            )}
          </div>

          <div className="p-6 border-b">
            <h2 className="text-xl font-semibold mb-4">Requirements</h2>
            <ul className="list-disc pl-5 text-gray-700">
              {tool.requirements.map((req, index) => (
                <li key={index} className="mb-1">{req}</li>
              ))}
            </ul>
          </div>

          <div className="p-6 flex flex-wrap gap-4">
            <Button className="flex items-center gap-2" onClick={handleDownload}>
              <Download className="h-4 w-4" /> Download Script
            </Button>
            <Button variant="outline" className="flex items-center gap-2">
              <Github className="h-4 w-4" /> View on GitHub
            </Button>
            <Button variant="outline" className="flex items-center gap-2">
              <ExternalLink className="h-4 w-4" /> Documentation
            </Button>
          </div>
        </div>

        <div className="mt-8 text-center text-gray-500 text-sm">
          <p>These scripts are for educational purposes only. Always obtain proper authorization before security testing.</p>
          <p className="mt-2">All tools are cross-platform and work on both Windows and Linux systems.</p>
        </div>
      </div>
    </div>
  );
};

export default ToolDetail;
