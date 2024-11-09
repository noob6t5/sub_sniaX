package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"sync"
	"golang.org/x/net/dns/dnsmessage"
)

const OpCodeQuery = 0  // package isn't working so manually added.

func main() {
	delay := flag.Int("delay", 1000, "Delay between requests in milliseconds")
	outputFile := flag.String("o", "", "Output file to save discovered subdomains")
	domainFile := flag.String("f", "", "File containing list of domains")
	singleDomain := flag.String("d", "", "Single domain to enumerate subdomains")
	flag.Parse()

	domains := loadDomains(*domainFile, *singleDomain)
	if len(domains) == 0 {
		fmt.Println("Usage: sub_sniaX -f <domain_file> or -d <single_domain> [-delay <ms>] [-o <output>]")
		os.Exit(1)
	}

	var output *os.File
	if *outputFile != "" {
		var err error
		output, err = os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Failed to create output file: %v\n", err)
		}
		defer output.Close()
	}

	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			// Normalize domain before processing
			normalizedDomain := normalizeDomain(domain)
			fmt.Printf("\nEnumerating subdomains for %s...\n\n", normalizedDomain)
			enumerateSubdomains(normalizedDomain, *delay, output)
		}(domain)
	}
	wg.Wait()
}

func loadDomains(domainFile, singleDomain string) []string {
	var domains []string
	if domainFile != "" {
		file, err := os.Open(domainFile)
		if err != nil {
			log.Fatalf("Failed to open domain file: %v\n", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			if domain != "" {
				domains = append(domains, domain)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Failed to read domain file: %v\n", err)
		}
	} else if singleDomain != "" {
		domains = append(domains, singleDomain)
	}
	return domains
}

func normalizeDomain(domain string) string {
	// Remove protocols (http://, https://)
	if strings.HasPrefix(domain, "https://") {
		domain = strings.TrimPrefix(domain, "https://")
	} else if strings.HasPrefix(domain, "http://") {
		domain = strings.TrimPrefix(domain, "http://")
	}

	// Remove 'www.' if present
	if strings.HasPrefix(domain, "www.") {
		domain = strings.TrimPrefix(domain, "www.")
	}

	return domain
}

func enumerateSubdomains(domain string, delay int, output *os.File) {
	nameServers, err := net.LookupNS(domain)
	if err != nil {
		log.Printf("Failed to get NS records for domain %s: %v\n", domain, err)
		return
	}

	var wg sync.WaitGroup
	for _, ns := range nameServers {
		wg.Add(1)
		go func(nsHost string) {
			defer wg.Done()
			fmt.Printf("Attempting AXFR on %-35s", domain+" via "+nsHost)
			subdomains := attemptAXFR(domain, nsHost, delay)
			if len(subdomains) == 0 {
				fmt.Println("AXFR failed or timed out.")
			}
			writeOutput(subdomains, output)
		}(ns.Host)
	}
	wg.Wait()

	// Optimizing CNAME chaining with batch DNS query
	fmt.Printf("\nAttempting CNAME chaining for %s...\n", domain)
	cnameChained := cnameChain(domain)
	writeOutput(cnameChained, output)

	// SNI enumeration in parallel
	fmt.Printf("\nAttempting SNI enumeration for %s...\n", domain)
	sniSubdomains := sniEnumerate(domain, delay)
	writeOutput(sniSubdomains, output)
}

func attemptAXFR(domain, ns string, delay int) []string {
	var result []string
	conn, err := net.Dial("tcp", ns+":53")
	if err != nil {
		log.Printf("Failed to connect to %s for AXFR: %v\n", ns, err)
		return result
	}
	defer conn.Close()

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			RecursionDesired: true,
			Response:         false,
			OpCode:           OpCodeQuery,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domain + "."),
				Type:  dnsmessage.TypeAXFR,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	buf, err := msg.Pack()
	if err != nil {
		log.Printf("Failed to pack AXFR request: %v\n", err)
		return result
	}

	for attempts := 0; attempts < 3; attempts++ {
		_, err = conn.Write(buf)
		if err != nil {
			log.Printf("Failed to send AXFR request: %v\n", err)
			return result
		}

		conn.SetReadDeadline(time.Now().Add(time.Duration(delay) * time.Millisecond))
		resBuf := make([]byte, 512)
		n, err := conn.Read(resBuf)
		if err != nil {
			log.Println("Error reading AXFR response or AXFR complete:", err)
			time.Sleep(2 * time.Second)
			continue
		}

		var resp dnsmessage.Message
		err = resp.Unpack(resBuf[:n])
		if err != nil {
			log.Printf("Failed to unpack AXFR response: %v\n", err)
			break
		}

		for _, answer := range resp.Answers {
			if answer.Header.Type == dnsmessage.TypeA || answer.Header.Type == dnsmessage.TypeCNAME {
				subdomain := strings.TrimSuffix(answer.Header.Name.String(), ".")
				result = append(result, subdomain)
				fmt.Println(" -", subdomain)
			}
		}
	}
	return result
}

func cnameChain(domain string) []string {
	var result []string
	cnames := make(map[string]bool) // Caching to avoid redundant lookups
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		log.Printf("Failed to lookup CNAME for %s: %v\n", domain, err)
		return result
	}
	for cname != domain {
		if _, seen := cnames[cname]; seen {
			break
		}
		cnames[cname] = true
		result = append(result, cname)
		cname, err = net.LookupCNAME(cname)
		if err != nil {
			break
		}
	}
	return result
}

func sniEnumerate(domain string, delay int) []string {
	commonSubdomains := []string{
		"www", "mail", "ftp", "webmail", "smtp", "portal", "vpn", "api", "dev", "test",
		"staging", "beta", "alpha", "dev-api", "sandbox", "preprod", "prod", "uat", "qa", "demo",
		"auth", "login", "register", "signup", "accounts", "user", "profile", "admin", "adminpanel",
		"help", "support", "docs", "documentation", "contact", "knowledgebase", "kb", "faq",
		"blog", "news", "media", "static", "images", "img", "cdn", "video", "assets", "resources",
		"shop", "store", "cart", "checkout", "order", "payments", "billing", "invoice", "pay",
		"analytics", "track", "tracking", "stats", "metrics", "data", "insights", "reports",
		"status", "monitor", "dashboard", "gateway", "node", "cdn", "proxy", "edge", "backup",
		"community", "forum", "discuss", "discussion", "social", "events", "meetup", "groups",
		"internal", "devtools", "tools", "config", "settings", "configurations",
		"developers", "developer", "api-docs", "api-portal", "graphql", "rest",
		"marketing", "promo", "offers", "campaign", "landing", "sales",
		"client", "userportal", "account", "my", "myaccount", "customer", "members", "portal",
		"app", "test1", "test2", "api-staging", "dashboard", "console", "manage", "sso", "single-sign-on",
		"backup", "service", "sync",
	}
	var result []string
	for _, subdomain := range commonSubdomains {
		addr := fmt.Sprintf("%s.%s", subdomain, domain)
		_, err := tls.Dial("tcp", addr+":443", &tls.Config{
			InsecureSkipVerify: true,
		})
		if err == nil {
			result = append(result, addr)
			fmt.Println(" - SNI detected:", addr)
		}
	}
	return result
}

func writeOutput(subdomains []string, output *os.File) {
	if len(subdomains) > 0 {
		for _, subdomain := range subdomains {
			fmt.Println(" -", subdomain)
			if output != nil {
				output.WriteString(subdomain + "\n")
			}
		}
	}
}
