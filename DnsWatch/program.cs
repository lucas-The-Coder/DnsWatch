using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace DnsWatch
{
    class Program
    {
        public static async Task<string[]> ResolveDomainAsync(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                return Array.Empty<string>();
            }

            try
            {
                IPAddress[] addresses = await Dns.GetHostAddressesAsync(domain);

                return addresses.Select(ip => ip.ToString()).ToArray();
            }
            catch
            {
                return Array.Empty<string>();
            }
        }

        public static async Task<(string domain, string[] ips, string status)> CheckDomainAsync(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                return (domain, Array.Empty<string>(), "INVALID");
            }

            string lower = domain.ToLower().Trim();

            if (lower.Contains(' ') || lower.Contains('_') || lower.Contains('@'))
            {
                return (domain, Array.Empty<string>(), "INVALID");
            }

            string[] ips = await ResolveDomainAsync(lower);

            if (ips.Length == 0)
            {
                return (domain, Array.Empty<string>(), "ERROR");
            }

            string status = "CLEAN";

            if (lower.StartsWith("xn--") || lower.Contains(".xn--"))
            {
                status = "SUSPICIOUS";
            }

            string[] suspiciousTlds = { ".tk", ".ml", ".xyz", ".top", ".click" };
            if (suspiciousTlds.Any(tld => lower.EndsWith(tld)))
            {
                status = "SUSPICIOUS";
            }

            string[] suspiciousKeywords = { "secure-login", "verify-", "-verify", "free-", "-free" };
            if (suspiciousKeywords.Any(kw => lower.Contains(kw)))
            {
                status = "SUSPICIOUS";
            }

            if (lower.Count(c => c == '.') > 3)
            {
                status = "SUSPICIOUS";
            }

            if (lower.Length > 63)
            {
                status = "SUSPICIOUS";
            }

            return (domain, ips, status);
        }

        public static string GetRiskLevel(string status)
        {
            if (status == "SUSPICIOUS")
            {
                return "HIGH";
            }

            if (status == "ERROR")
            {
                return "MEDIUM";
            }

            if (status == "INVALID")
            {
                return "MEDIUM";
            }

            return "LOW";
        }

        public static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: dotnet run -- <domain>");
                return;
            }

            string domain = args[0];

            var result = await CheckDomainAsync(domain);

            string risk = GetRiskLevel(result.status);

            Console.WriteLine($"Domain: {result.domain}");
            Console.WriteLine("IPs:");
            if (result.ips.Length == 0)
            {
                Console.WriteLine("  None");
            }
            else
            {
                foreach (string ip in result.ips)
                {
                    Console.WriteLine($"  - {ip}");
                }
            }
            Console.WriteLine($"Status: {result.status}");
            Console.WriteLine($"Risk:   {risk}");

            return;
        }
    }
}