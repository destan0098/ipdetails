package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/tealeg/xlsx"
	"github.com/urfave/cli/v2"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var outputfilename, outputfiletype string
var timeout int
var start time.Time
var xlsxFile *xlsx.File

const maxRetry = 5

type Res struct {
	IP                   string
	InfrastructureLevel1 string `json:"infrastructure_level1,omitempty"`
	InfrastructureLevel2 string `json:"infrastructure_level2,omitempty"`
	InfrastructureLevel3 string `json:"infrastructure_level3,omitempty"`
	IPFrom               string `json:"ip_from,omitempty"`
	IPTo                 string `json:"ip_to,omitempty"`
	CountryCode          string `json:"country_code,omitempty"`
	CityName             string `json:"city_name,omitempty"`
	Latitude             string `json:"latitude,omitempty"`
	Longitude            string `json:"longitude,omitempty"`
	ISP                  string `json:"isp,omitempty"`
	RegionName           string `json:"region_name,omitempty"`
	Title                string `json:"title,omitempty"`
	CIDR                 string `json:"cidr,omitempty"`
	Host                 string `json:"host,omitempty"`
	LastUpdate           string `json:"last_update,omitempty"`
}

type ipinfo struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Anycast  bool   `json:"anycast,omitempty"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
	Loc      string `json:"loc,omitempty"`
	Org      string `json:"org,omitempty"`
	Postal   string `json:"postal,omitempty"`
	Timezone string `json:"timezone,omitempty"`
	Readme   string `json:"readme,omitempty"`
}
type BgpView struct {
	Status        string `json:"status,omitempty"`
	StatusMessage string `json:"status_message,omitempty"`
	Data          struct {
		IP        string `json:"ip,omitempty"`
		PtrRecord string `json:"ptr_record,omitempty"`
		Prefixes  []struct {
			Prefix string `json:"prefix,omitempty"`
			IP     string `json:"ip,omitempty"`
			Cidr   int    `json:"cidr,omitempty"`
			Asn    struct {
				Asn         int    `json:"asn,omitempty"`
				Name        string `json:"name,omitempty"`
				Description string `json:"description,omitempty"`
				CountryCode string `json:"country_code,omitempty"`
			} `json:"asn,omitempty"`
			Name        string `json:"name,omitempty"`
			Description string `json:"description,omitempty"`
			CountryCode string `json:"country_code,omitempty"`
		} `json:"prefixes,omitempty"`
		RirAllocation struct {
			RirName          string `json:"rir_name,omitempty"`
			CountryCode      any    `json:"country_code,omitempty"`
			IP               string `json:"ip,omitempty"`
			Cidr             int    `json:"cidr,omitempty"`
			Prefix           string `json:"prefix,omitempty"`
			DateAllocated    string `json:"date_allocated,omitempty"`
			AllocationStatus string `json:"allocation_status,omitempty"`
		} `json:"rir_allocation,omitempty"`
		IanaAssignment struct {
			AssignmentStatus string `json:"assignment_status,omitempty"`
			Description      string `json:"description,omitempty"`
			WhoisServer      string `json:"whois_server,omitempty"`
			DateAssigned     any    `json:"date_assigned,omitempty"`
		} `json:"iana_assignment,omitempty"`
		Maxmind struct {
			CountryCode any `json:"country_code,omitempty"`
			City        any `json:"city,omitempty"`
		} `json:"maxmind,omitempty"`
	} `json:"data,omitempty"`
	Meta struct {
		TimeZone      string `json:"time_zone,omitempty"`
		APIVersion    int    `json:"api_version,omitempty"`
		ExecutionTime string `json:"execution_time,omitempty"`
	} `json:"@meta,omitempty"`
}

var ipresult = make(map[string][]Res)

func getStartEndIP(cidrip string) (net.IP, net.IP) {
	// Convert network mask to 32-bit mask
	ip, ipnet, err := net.ParseCIDR(cidrip)
	if err != nil {
		fmt.Printf("Error parsing CIDR: %v\n", err)
		os.Exit(1)
	}
	startIP := ip.Mask(ipnet.Mask)
	endIP := make(net.IP, len(startIP))
	for i := range startIP {
		endIP[i] = startIP[i] | ^ipnet.Mask[i]
	}

	return startIP, endIP
}
func withPipe() {
	var ip string
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		ip = scanner.Text()

		datamin(ip)
	}

}
func hosttoip(urls string) string {
	var ipAddr string
	var err error
	ip := net.ParseIP(urls)
	if ip != nil {
		ipAddr = urls
	} else {
		// If it's not an IP address, try resolving it as a domain
		ipAddr, err = resolveDomain(urls)
		if err != nil {
			fmt.Printf("Error resolving domain: %v\n", err)
			os.Exit(1)
		}

	}
	return ipAddr
}
func withList(inputFile string) {
	IPs := readIPS(inputFile)

	for _, ip := range IPs {
		datamin(ip)

	}
}
func readIPS(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	var ipss []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipss = append(ipss, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return ipss
}

func main() {
	app := &cli.App{
		Flags: []cli.Flag{

			&cli.StringFlag{
				Name:    "list",
				Value:   "",
				Aliases: []string{"l"},
				Usage:   "Enter a list from a text file",
			},
			&cli.BoolFlag{
				Name:    "pipe",
				Aliases: []string{"p"},
				Usage:   "Enter just from a pipeline",
			},

			&cli.IntFlag{
				Name:        "timeout",
				Aliases:     []string{"t"},
				Value:       2,
				Usage:       "Time out Port Scanning in second ",
				Destination: &timeout,
			},
			&cli.StringFlag{
				Name:        "filename",
				Aliases:     []string{"f"},
				Value:       "test",
				Usage:       "output file name",
				Destination: &outputfilename,
			},
			&cli.StringFlag{
				Name:        "type",
				Aliases:     []string{"y"},
				Value:       "csv",
				Usage:       "output file type json or csv or excel",
				Destination: &outputfiletype,
			},
		},
		Action: func(cCtx *cli.Context) error {

			start = time.Now()
			switch {

			case cCtx.String("list") != "":
				withList(cCtx.String("list"))
			case cCtx.Bool("pipe"):
				withPipe()
			}

			elapsed := time.Since(start)

			fmt.Printf(color.Colorize(color.Red, "[*] Finish Job in  %s \n"), elapsed)
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

}
func titleshow(urls string) (string, bool) {
	ipurl := fmt.Sprintf("http://%s", urls)

	//fmt.Println(ipurl)
	spaceClient := http.Client{
		Timeout: time.Second * time.Duration(timeout), // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, ipurl, nil)
	if err != nil {
		return "", true
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0")

	res, getErr := spaceClient.Do(req)
	if getErr != nil {

		return "", true

	}
	defer res.Body.Close()
	tokenizer := html.NewTokenizer(res.Body)
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			// End of the document
			//	fmt.Println("Title not found.")
			return "", true
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data == "title" {
				// Move to the next token to get the title content
				tokenType = tokenizer.Next()
				if tokenType == html.TextToken {
					// Print the title content
					//fmt.Printf("Title: %s\n", tokenizer.Token().Data)
					return tokenizer.Token().Data, false
				}
			}
		}
	}
	return tokenizer.Token().Data, false

}

func datamin(urls string) {
	var long, lat string
	var latlong []string
	var title string
	var errs bool
	var lenss int
	ipadd := hosttoip(urls)
	det, err := asnshow(ipadd)
	if err != nil {
		return
	}
	lenss = len(det.Data.Prefixes)
	lenss--
	startIP, endIP := getStartEndIP(det.Data.RirAllocation.Prefix)
	title, errs = titleshow(ipadd)
	if errs {
		title = ""
	}
	fmt.Printf(color.Colorize(color.Green, "[ + ] Scanning IP %s \n"), ipadd)
	if det.Status == "ok" {
		det2, err := IpInfo(ipadd)
		if err != nil {
			return
		}
		loc := det2.Loc
		if len(loc) > 0 {
			latlong = strings.Split(loc, ",")
			lat = latlong[0]
			long = latlong[1]
		}
		if len(det.Data.Prefixes) == 0 {
			m := Res{ipadd, "*", "*", "*", startIP.String(), endIP.String(), det2.Country, det2.City, lat, long, det2.Org, det2.Region, title, det.Data.RirAllocation.Prefix, det2.Hostname, det.Data.RirAllocation.DateAllocated}
			// Append directly to the map
			ipresult[ipadd] = append(ipresult[ipadd], m)

			if outputfiletype == "csv" {
				writeResultscsv(ipadd, "*", "*", "*", startIP.String(), endIP.String(), det2.Country, det2.City, lat, long, det2.Org, det2.Region, title, det.Data.RirAllocation.Prefix, det2.Hostname, det.Data.RirAllocation.DateAllocated)
			} else if outputfiletype == "json" {
				writeResultsjson(ipresult)
			} else if outputfiletype == "excel" {
				writeResultsxls(ipadd, "*", "*", "*", startIP.String(), endIP.String(), det2.Country, det2.City, lat, long, det2.Org, det2.Region, title, det.Data.RirAllocation.Prefix, det2.Hostname, det.Data.RirAllocation.DateAllocated)

			} else {
				fmt.Println("Enter json or csv")
			}
		} else {
			m := Res{ipadd, "*", "*", "*", startIP.String(), endIP.String(), det2.Country, det2.City, lat, long, det2.Org, det2.Region, title, det.Data.RirAllocation.Prefix, det2.Hostname, det.Data.RirAllocation.DateAllocated}
			// Append directly to the map
			ipresult[ipadd] = append(ipresult[ipadd], m)

			if outputfiletype == "csv" {
				writeResultscsv(ipadd, "*", "*", "*", startIP.String(), endIP.String(), det2.Country, det2.City, lat, long, det2.Org, det2.Region, title, det.Data.Prefixes[0].Prefix, det2.Hostname, det.Data.RirAllocation.DateAllocated)
			} else if outputfiletype == "json" {
				writeResultsjson(ipresult)
			} else if outputfiletype == "excel" {
				writeResultsxls(ipadd, "*", "*", "*", startIP.String(), endIP.String(), det2.Country, det2.City, lat, long, det2.Org, det2.Region, title, det.Data.Prefixes[0].Prefix, det2.Hostname, det.Data.RirAllocation.DateAllocated)

			} else {
				fmt.Println("Enter json or csv")
			}
		}
	} else {
		fmt.Printf(color.Colorize(color.Red, "[-] Not find info for ip %s , please check ip\n"), ipadd)
	}
}

func resolveDomain(domain string) (string, error) {
	for i := 0; i <= maxRetry; i++ {
		addrs, err := net.LookupIP(domain)
		if err != nil {
			return "", err
		}
		if len(addrs) == 0 {
			return "", fmt.Errorf("no IP addresses found for domain")
		}
		return addrs[0].String(), nil
	}
	return "", fmt.Errorf("no IP addresses found for domain")
}

func IpInfo(urls string) (ipinfo, error) {

	////	fmt.Println(urls)
	var json_resp ipinfo
	ipAddr := urls
	//fmt.Println(ips[0])
	ipurl := fmt.Sprintf("https://ipinfo.io/%s/json", ipAddr)

	//fmt.Println(ipurl)
	spaceClient := http.Client{
		Timeout: time.Second * time.Duration(timeout), // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, ipurl, nil)
	if err != nil {
		return ipinfo{}, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0")

	res, getErr := spaceClient.Do(req)
	if getErr != nil {

		return ipinfo{}, err

	}
	if res.StatusCode == http.StatusTooManyRequests {
		check429(ipAddr)
	}
	if res.Body != nil {
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				fmt.Println("Error Line 115")
			}
		}(res.Body)
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {

		return ipinfo{}, err

	}

	jsonErr := json.Unmarshal(body, &json_resp)

	if jsonErr != nil {

		return ipinfo{}, err

	}

	return json_resp, nil
}
func check429(ipAddr string) {

	file, err := os.Create("429.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Println(err)
		}
	}(file)

	line := ipAddr
	if _, err := file.WriteString(line); err != nil {
		log.Println(err)
	}

}
func asnshow(ipAddr string) (BgpView, error) {

	var err error

	var jsonasn_resp BgpView

	ipurl := fmt.Sprintf("https://api.bgpview.io/ip/%s", ipAddr)
	spaceClient := http.Client{
		Timeout: time.Second * time.Duration(timeout), // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, ipurl, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0")

	res, getErr := spaceClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}
	if res.StatusCode == http.StatusTooManyRequests {
		check429(ipAddr)
	}

	if res.Body != nil {
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				fmt.Println("Error Line 177")
			}
		}(res.Body)
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	jsonErr := json.Unmarshal(body, &jsonasn_resp)
	if jsonErr != nil {
		return BgpView{}, jsonErr
	}

	return jsonasn_resp, nil
}

var omiFile *os.File

func writeResultscsv(ip, infrastructure_level1, infrastructure_level2, infrastructure_level3,
	ip_from, ip_to, country_code, city_name, latitude, longitude, isp, region_name, title, cidr, host, last_update string) {

	path := "output"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}

	omiFile, err := os.OpenFile(fmt.Sprintf("output/%s.csv", outputfilename), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer omiFile.Close()

	// Write header only if the file is newly created
	fileInfo, err := omiFile.Stat()
	if err != nil {
		log.Fatal(err)
	}

	if fileInfo.Size() == 0 {
		writeCSVFile(omiFile, "ip", "infrastructure_level1", "infrastructure_level2", "infrastructure_level3",
			"ip_from", "ip_to", "country_code", "city_name", "latitude", "longitude", "isp", "region_name", "title", "cidr", "host", "last_update")
	}

	writeCSVFile(omiFile, ip, infrastructure_level1, infrastructure_level2, infrastructure_level3,
		ip_from, ip_to, country_code, city_name, latitude, longitude, isp, region_name, title, cidr, host, last_update)
}

func writeCSVFile(file *os.File, values ...string) {
	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write(values); err != nil {
		log.Fatal(err)
	}
}

// ///////////
func writeResultsxls(values ...string) {
	path := "output"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}

	xlsxFilePath := fmt.Sprintf("output/%s.xlsx", outputfilename)

	var xlsxFile *xlsx.File

	if _, err := os.Stat(xlsxFilePath); os.IsNotExist(err) {
		// Create new xlsx file and add header
		xlsxFile = xlsx.NewFile()
		sheet, err := xlsxFile.AddSheet("Sheet1")
		if err != nil {
			log.Fatal(err)
		}

		// Write header only if the file is newly created
		writeExcelFile(sheet, "ip", "infrastructure_level1", "infrastructure_level2", "infrastructure_level3",
			"ip_from", "ip_to", "country_code", "city_name", "latitude", "longitude", "isp", "region_name", "title", "cidr", "host", "last_update")
	} else {
		// Open existing xlsx file
		xlsxFile, err = xlsx.OpenFile(xlsxFilePath)
		if err != nil {
			log.Fatal(err)
		}
	}

	sheet := xlsxFile.Sheets[0]

	// Write data to the sheet
	writeExcelFile(sheet, values...)

	// Save the xlsx file
	if err := xlsxFile.Save(xlsxFilePath); err != nil {
		log.Fatal(err)
	}
}

func writeExcelFile(sheet *xlsx.Sheet, values ...string) {
	row := sheet.AddRow()
	for _, value := range values {
		cell := row.AddCell()
		cell.SetString(value)
	}
}

// //////////////
func writeResultsjson(results map[string][]Res) {

	path := "output"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}

	omiFile, err := os.Create(fmt.Sprintf("output/%s.json", outputfilename))
	if err != nil {
		log.Fatal(err)
	}
	defer omiFile.Close()
	writeJSONFile(omiFile, results)
	// Write header only if the file is newly created

}

func writeJSONFile(file *os.File, results map[string][]Res) {
	// Create a map to store the simplified output
	jsonData, err := json.MarshalIndent(results, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	// Write the JSON data to the file
	if _, err := file.Write(jsonData); err != nil {
		log.Fatal(err)
	}
}
