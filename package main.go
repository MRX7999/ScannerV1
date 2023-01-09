package main


import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/owasp/go-cwe-top10"
	"github.com/owasp/go-owasp-top-ten"
	"github.com/shodan-io/shodan-go"
	//"github.com/shodan-api/shodan"
	//"github.com/ns3777k/go-shodan/v4/shodan"
)

// Passive OSINT function
func gatherInfo(url string) (emails []string, phones []string, addresses []string) {
	// Scrape website for information
	response, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer response.Body.Close()

	// Look for email addresses
	emailRegex := regexp.MustCompile(`[\w\.-]+@[\w\.-]+`)
	emails = emailRegex.FindAllString(response, -1)

	// Look for phone numbers
	phoneRegex := regexp.MustCompile(`\d{3}-\d{3}-\d{4}`)
	phones = phoneRegex.FindAllString(response, -1)

	// Look for addresses
	addressRegex := regexp.MustCompile(`\b\d{1,5} [\w\s]+, [A-Za-z]{2} \d{5}\b`)
	addresses = addressRegex.FindAllString(response, -1)
	return
}

// Vulnerability scanner function
func scanVulnerabilities(url string) (owaspVulnerabilities []string, cweVulnerabilities []string, sslValidFrom string, sslValidTo string, shodanResults []string) {
	// Check for OWASP Top 10 vulnerabilities
	vulnerabilities, err := owaspTopTen.GetVulnerabilities(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	owaspVulnerabilities = vulnerabilities

	// Check for CWE Top 10 vulnerabilities
	vulnerabilities, err = cweTop10.GetVulnerabilities(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	cweVulnerabilities = vulnerabilities

	// Check SSL certificate
	conn, err := tls.Dial("tcp", url, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	validFrom := certs[0].NotBefore
	validTo := certs[0].NotAfter
	sslValidFrom = validFrom.String()
	sslValidTo = validTo.String()

	// Check Shodan API
	client := shodan.NewClient(nil)
	hostSearch, err := client.HostSearch(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, match := range hostSearch.Matches {
		shodanResults = append(shodanResults, match.IPString+" "+match.Data)
	}
	return
}

// Function to generate a list of base subdomains to scan
func generateSubdomains(domain string) []string {
	subdomains := []string{}
	// Add common subdomains to list
	commonSubdomains := []string{"www", "mail", "ftp", "webmail", "remote", "api", "docs"}
	for _, subdomain := range commonSubdomains { 		subdomains = append(subdomains, subdomain+"."+domain)
}
return subdomains
}

func main() {
// Prompt user for domain to scan
fmt.Println("Enter a domain to scan:")
reader := bufio.NewReader(os.Stdin)
domain, _ := reader.ReadString('\n')
domain = strings.TrimSpace(domain)

// Generate list of subdomains to scan
subdomains := generateSubdomains(domain)

// Create CSV file to store results
file, err := os.Create("scan_results.csv")
if err != nil {
	fmt.Println(err)
	return
}
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()

// Write headers to CSV file
headers := []string{"Subdomain", "Email Addresses", "Phone Numbers", "Addresses", "OWASP Vulnerabilities", "CWE Vulnerabilities", "SSL Valid From", "SSL Valid To", "Shodan Results"}
err = writer.Write(headers)
if err != nil {
	fmt.Println(err)
	return
}

// Scan each subdomain for vulnerabilities and gather information
for _, subdomain := range subdomains {
	fmt.Println("Scanning", subdomain)
	emails, phones, addresses := gatherInfo(subdomain)
	owaspVulnerabilities, cweVulnerabilities, sslValidFrom, sslValidTo, shodanResults := scanVulnerabilities(subdomain)
	// Write results to CSV file
	record := []string{subdomain, strings.Join(emails, ","), strings.Join(phones, ","), strings.Join(addresses, ","), strings.Join(owaspVulnerabilities, ","), strings.Join(cweVulnerabilities, ","), sslValidFrom, sslValidTo, strings.Join(shodanResults, ",")}
	err := writer.Write(record)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println()
}
}

		
