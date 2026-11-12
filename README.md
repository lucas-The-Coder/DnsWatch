# DnsWatch

Resolve a domain to IPs and check if it looks suspicious. Backend only, C# console app.

Uses async DNS lookup, checks for punycode, suspicious TLDs, phishing keywords, too many subdomains, and long domains, and reports a status and risk level for SOC triage.

## Features

- Async DNS lookup with `Dns.GetHostAddressesAsync`
- Resolves domain to list of IPs
- Checks for `xn--` punycode, a common phishing trick
- Checks for suspicious TLDs like `.tk`, `.ml`, `.xyz`, `.top`, `.click`
- Checks for phishing keywords like `secure-login`, `verify`, `free`
- Checks for too many subdomains, more than 3 dots
- Checks for long domains, more than 63 chars
- Handles empty, invalid, and non existent domains without crash
- No printing inside helpers, only `Main` prints

## Project Structure

- `Program.cs` - Main app, all 4 methods
- `DnsWatch.csproj` - Project file, .NET 8.0

## How to Run

```bash
dotnet run -- <domain>
dotnet run
