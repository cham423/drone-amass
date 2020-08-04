package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
)

const (
	version = "1.0.0"
	tool    = "drone-amass"
	usage   = `
Parses OWASP Amass JSON output into a lair project.
Usage:
  drone-amass [options] <id> <filename>
  export LAIR_ID=<id>; drone-amass [options] <filename>
Options:
  -version			show version and exit
  -verbose			enable verbose output
  -h              show usage and exit
  -k              allow insecure SSL connections
  -tags           a comma separated list of tags to add to every host that is imported
  -force-hosts    import all hosts into Lair, default behaviour is to only import
                  hostnames for hosts that already exist in a project
  -force-ports    disable data protection in the API server for excessive ports
  -safe-netblocks	disable adding all netblock results from amass, and instead only add netblocks
					that were already present in the lair project.
`
)

// Author: cham423
// this tool can parse the json output (generated with the -json option in amass) from either the intel or enum subcommands in amass.
// example command: "amass enum -json out.json -d example.com"
// drones behave weirdly in the best of times, so export/backup your project before running to avoid any data loss.
// CURRENT BUGS:
// - netblock and host imports do not work if there is not already at least one host and/or netblock added to the lair project before import
// - when hosts are added with -force-hosts, they will show up with the green status for some reason

// this is what the amass json output format looks like:
type amassResult struct {
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	Addresses []struct {
		IP   string `json:"ip"`
		Cidr string `json:"cidr"`
		Asn  int    `json:"asn"`
		Desc string `json:"desc"`
	} `json:"addresses"`
	Tag    string `json:"tag"`
	Source string `json:"source"`
}

// parse amass results file
// this recursive function takes the byte array "data" which is the raw data read from the amass output file which is jsonlines format
// it takes this data and decodes each json line, and returns it
func parseJsonLines(data []byte, f func(amassResult)) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var result amassResult
		err := dec.Decode(&result)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		f(result)
	}
}

func main() {
	showVersion := flag.Bool("version", false, "")
	verboseOut := flag.Bool("verbose", false, "")
	insecureSSL := flag.Bool("k", false, "")
	forcePorts := flag.Bool("force-ports", false, "")
	forceHosts := flag.Bool("force-hosts", false, "")
	safeNetblocks := flag.Bool("safe-netblocks", false, "")
	tags := flag.String("tags", "", "")
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	// if version flag given, print version and exit
	if *showVersion {
		log.Println(version)
		os.Exit(0)
	}
	// check for required environment variables
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	// use lair project ID from environment variable if present
	lairPID := os.Getenv("LAIR_ID")

	// read filename and project ID arguments
	var filename string
	switch len(flag.Args()) {
	case 2:
		lairPID = flag.Arg(0)
		filename = flag.Arg(1)
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}
	if lairPID == "" {
		log.Fatal("Fatal: Missing LAIR_ID")
	}
	// validate given lair URL
	u, err := url.Parse(lairURL)
	if err != nil {
		log.Fatalf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	// validate given credentials
	if u.User == nil {
		log.Fatal("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Fatal: Missing username and/or password")
	}
	// create lair API client
	lairClient, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: *insecureSSL,
	})
	if err != nil {
		log.Fatalf("Fatal: Error setting up client: Error %s", err.Error())
	}
	// read file into "data" variable
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Fatal: Could not open file. Error %s", err.Error())
	}
	// parse tags given as arguments
	hostTags := []string{}
	if *tags != "" {
		hostTags = strings.Split(*tags, ",")
	}
	// create a map (aka hashtable) of with a string and bool "column"
	tagSet := map[string]bool{}

	// create empty array of results
	var aResults []amassResult
	// call the function to parse the raw jsonlines file contents from amass into an array of json strings "aResults"
	parseJsonLines(data, func(result amassResult) {
		if *verboseOut {
			fmt.Printf("got amass json result %v\n", result)
		}
		aResults = append(aResults, result)
	})

	// define results as slice of amassResults
	type Results []amassResult

	// create maps for  with a string and result "column"
	hNotFound := map[string]Results{}
	nNotFound := map[string]Results{}

	// grab lair project from lair API and store in variable
	exproject, err := lairClient.ExportProject(lairPID)
	if err != nil {
		log.Fatalf("Fatal: Unable to export project. Error %s", err.Error())
		if *verboseOut {
			fmt.Printf("project: %v", exproject)

		}
	}

	// create empty project variable to store merged content in later
	project := &lair.Project{
		ID:   lairPID,
		Tool: tool,
		Commands: []lair.Command{lair.Command{
			Tool: tool,
		}},
	}
	// iterate through results for lair Hosts, append IP addresss matches to exproject for merging later
	for _, result := range aResults {
		found := false
		if !strings.Contains(result.Name, "*") {
			for i := range exproject.Hosts {
				h := exproject.Hosts[i]
				for _, address := range result.Addresses {
					if *verboseOut {
						fmt.Printf("%s has IP address: %s\n", result.Name, address.IP)
					}
					if address.IP == h.IPv4 {
						exproject.Hosts[i].Hostnames = append(exproject.Hosts[i].Hostnames, result.Name)
						exproject.Hosts[i].LastModifiedBy = tool
						found = true
						if _, ok := tagSet[h.IPv4]; !ok {
							tagSet[h.IPv4] = true
							exproject.Hosts[i].Tags = append(exproject.Hosts[i].Tags, hostTags...)
						}
					}
					if !found {
						hNotFound[address.IP] = append(hNotFound[address.IP], result)
					}
				}
			}
		}
	}
	// append results to hosts
	for _, h := range exproject.Hosts {
		project.Hosts = append(project.Hosts, lair.Host{
			IPv4:           h.IPv4,
			LongIPv4Addr:   h.LongIPv4Addr,
			IsFlagged:      h.IsFlagged,
			LastModifiedBy: h.LastModifiedBy,
			MAC:            h.MAC,
			OS:             h.OS,
			Status:         h.Status,
			StatusMessage:  h.StatusMessage,
			Tags:           hostTags,
			Hostnames:      h.Hostnames,
		})
	}
	// if forceHosts was specified, add all hosts that weren't previously in lair to the project along with their hostnames
	if *forceHosts {
		fmt.Printf("force hosts was specified, adding all hosts from amass into lair project\n")
		for ip, results := range hNotFound {
			hostnames := []string{}
			for _, r := range results {
				hostnames = append(hostnames, r.Name)
			}
			project.Hosts = append(project.Hosts, lair.Host{
				IPv4:      ip,
				Hostnames: hostnames,
				Status:    lair.StatusGrey,
			})
		}
	}

	// iterate through results for lair Netblocks, matching CIDRs will get appended to exproject for merging later
	// unlike with hosts, the default behavior here is to add netblocks even if they didn't exist before.
	for _, result := range aResults {
		for i := range exproject.Netblocks {
			h := exproject.Netblocks[i]
			for _, address := range result.Addresses {
				if *verboseOut {
					fmt.Printf("%s has Netblock %s\n", result.Name, address.Cidr)
				}
				if !*safeNetblocks {
					asnString := strconv.Itoa(address.Asn)
					project.Netblocks = append(project.Netblocks, lair.Netblock{
						ASN:         asnString,
						CIDR:        address.Cidr,
						Description: address.Desc,
					})
				}
				if address.Cidr != h.CIDR {
					nNotFound[address.Cidr] = append(nNotFound[address.Cidr], result)
				}
			}
		}
	}

	// send the modified project to lair
	res, err := lairClient.ImportProject(&client.DOptions{ForcePorts: *forcePorts}, project)
	if err != nil {
		log.Fatalf("Fatal: Unable to import project. Error %s", err)
	}
	defer res.Body.Close()
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Fatal: Error %s", err.Error())
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		log.Fatalf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		log.Fatalf("Fatal: Import failed. Error %s", droneRes.Message)
	}
	if len(hNotFound) > 0 {
		if *forceHosts {
			log.Println("Info: The following hosts had hostnames and were forced to import into lair")
		} else {
			log.Println("Info: The following hosts had hostnames but could not be imported because they either had wildcard hostnames or do not exist in lair")
		}
	}
	for k := range hNotFound {
		fmt.Println(k)
	}
	if len(nNotFound) > 0 {
		if *safeNetblocks {
			log.Println("Info: The following netblocks were not imported into lair because they were not present before import")
		} else {
			log.Println("Info: The following netblocks were not present in the project, and were added")
		}
	}
	for k := range nNotFound {
		fmt.Println(k)
	}
	log.Println("Success: Operation completed successfully")
}
