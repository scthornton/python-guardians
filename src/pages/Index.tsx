
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Terminal, Lock, Search, Database, FileDigit, Globe, Bug, Hash, Network } from "lucide-react";
import { Link } from "react-router-dom";

const Index = () => {
  const securityTools = [
    {
      id: 1,
      name: "Log Analyzer",
      description: "Analyzes authentication logs to detect suspicious login attempts and potential brute force attacks.",
      icon: <FileDigit className="h-8 w-8 text-blue-500" />,
      script: "log_analyzer.py"
    },
    {
      id: 2,
      name: "Port Scanner",
      description: "Performs TCP port scanning on target hosts to identify open ports and running services.",
      icon: <Network className="h-8 w-8 text-green-500" />,
      script: "port_scanner.py"
    },
    {
      id: 3,
      name: "Password Checker",
      description: "Evaluates password strength based on length, complexity, and common password lists.",
      icon: <Lock className="h-8 w-8 text-red-500" />,
      script: "password_checker.py"
    },
    {
      id: 4,
      name: "Directory Bruteforce",
      description: "Attempts to discover hidden directories and files on web servers through brute force.",
      icon: <Search className="h-8 w-8 text-purple-500" />,
      script: "directory_bruteforce.py"
    },
    {
      id: 5,
      name: "Packet Sniffer",
      description: "Captures and analyzes network packets to monitor network traffic.",
      icon: <Terminal className="h-8 w-8 text-yellow-500" />,
      script: "packet_sniffer.py"
    },
    {
      id: 6,
      name: "File Integrity Monitor",
      description: "Monitors changes to critical files by checking file hashes at regular intervals.",
      icon: <Shield className="h-8 w-8 text-indigo-500" />,
      script: "file_integrity_monitor.py"
    },
    {
      id: 7,
      name: "Subdomain Enumeration",
      description: "Enumerates subdomains of a target domain using various techniques.",
      icon: <Globe className="h-8 w-8 text-teal-500" />,
      script: "subdomain_enum.py"
    },
    {
      id: 8,
      name: "Web Vulnerability Scanner",
      description: "Scans websites for common vulnerabilities like XSS, SQLi, and open redirects.",
      icon: <Bug className="h-8 w-8 text-orange-500" />,
      script: "web_vuln_scanner.py"
    },
    {
      id: 9,
      name: "DNS Reconnaissance",
      description: "Gathers DNS information about domains and IP addresses.",
      icon: <Database className="h-8 w-8 text-cyan-500" />,
      script: "dns_recon.py"
    },
    {
      id: 10,
      name: "Hash Cracker",
      description: "Attempts to crack password hashes using dictionary and brute force methods.",
      icon: <Hash className="h-8 w-8 text-pink-500" />,
      script: "hash_cracker.py"
    }
  ];

  const handleDownload = (script) => {
    // This would be implemented if we were to enable actual downloads
    console.log(`Downloading ${script}`);
  };

  return (
    <div className="min-h-screen bg-gray-50 py-10 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-extrabold text-gray-900 sm:text-5xl sm:tracking-tight lg:text-6xl">
            Python Security Tools Collection
          </h1>
          <p className="max-w-xl mt-5 mx-auto text-xl text-gray-500">
            A suite of 10 Python scripts for various security-related tasks, from log analysis to penetration testing.
          </p>
        </div>

        <div className="mt-10">
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {securityTools.map((tool) => (
              <Card key={tool.id} className="border border-gray-200 hover:shadow-lg transition-shadow duration-300">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-xl font-bold">{tool.name}</CardTitle>
                    <div className="rounded-full p-2 bg-gray-100">{tool.icon}</div>
                  </div>
                  <CardDescription className="text-gray-600 mt-2">
                    {tool.description}
                  </CardDescription>
                </CardHeader>
                <CardFooter>
                  <Button 
                    className="w-full" 
                    variant="outline"
                    asChild
                  >
                    <Link to={`/tool/${tool.id}`}>View Details</Link>
                  </Button>
                </CardFooter>
              </Card>
            ))}
          </div>
        </div>

        <div className="mt-16 text-center">
          <div className="p-6 bg-white shadow-md rounded-lg">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Usage Notes</h2>
            <ul className="text-left text-gray-600 space-y-2 max-w-3xl mx-auto">
              <li>• These scripts are provided for educational purposes and legitimate security testing only</li>
              <li>• Always obtain proper authorization before testing on systems you don't own</li>
              <li>• Some scripts may require additional Python packages (requirements noted in each script)</li>
              <li>• Run scripts with Python 3.6+ for best compatibility</li>
            </ul>
          </div>
        </div>

        <footer className="mt-16 text-center text-gray-500">
          <p>© {new Date().getFullYear()} Scott Thornton. All tools are for educational and security research purposes.</p>
        </footer>
      </div>
    </div>
  );
};

export default Index;
