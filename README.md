# sub_sniaX
A tool to do subdomain enumeration using DNS AXFR (zone transfer) and SNI (Server Name Indication) methods.

<img src="https://github.com/user-attachments/assets/874c7ea6-5050-4870-9408-756a54ea9dd1" alt="icon" width="200" height="200">


## Features

- **DNS AXFR**: Attempts DNS zone transfers to find additional subdomains (useful for misconfigured DNS servers).
- **CNAME Chaining**: Resolves CNAME records and follows chains to discover further subdomains.
- **SNI Enumeration**: Uses the TLS SNI extension to discover subdomains that are publicly accessible via HTTPS.
- **Configurable Delay**: Option to add a delay between requests to avoid rate-limiting.

## Installation 

Ensure that Go is installed and your `$GOPATH` is set correctly.

```
go install github.com/noob6t5/sub_sniaX@latest

```
For a **single domain**, This is the recommended method.

`sub_sniaX -d domain.com -o output.txt -delay 1000`


# Options

-d: The target domain (e.g., example.com).

-o: Output file where found subdomains will be saved (e.g., output.txt).

-delay: Delay between requests in milliseconds (e.g., 1000 for 1 second).

-f: Input file containing domains, one per line.

**Multple Domain** :  `sub_sniaX -f domains.txt  -delay 1500`

# Todo

- [ ] Use Stdin Method
- [ ] Add more bypasses
- [ ] Handle custom input file for SNI from user

