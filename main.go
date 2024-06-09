package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gorilla/feeds"
	"github.com/vulncheck-oss/sdk"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
)

func main() {

	//human-friendly CLI output
	log.SetHandler(cli.New(os.Stderr))

	//set the logging level
	log.SetLevel(log.WarnLevel)

	// read API key from environment variable
	VULNCHECK_TOKEN := os.Getenv("VULNCHECK_TOKEN")
	if VULNCHECK_TOKEN == "" {
		log.Fatal("VULNCHECK_TOKEN environment variable not set")

	}

	client := sdk.Connect("https://api.vulncheck.com", VULNCHECK_TOKEN)

	response, err := client.GetIndexVulncheckKev(sdk.IndexQueryParameters{Limit: 2, Sort: "date_added"})
	if err != nil {
		log.WithError(err).Fatal("Error getting index")
	}

	now := time.Now()
	feed := &feeds.Feed{
		Title:       "Vulncheck KEV",
		Link:        &feeds.Link{Href: "https://vulncheck.com/browse/kev"},
		Description: "Newly added vulnerabilities to the VulnCheck KEV database",
		Author:      &feeds.Author{Name: "Data courtesy of VulnCheck"},
		Created:     now,
	}

	for _, vuln := range response.Data {
		dateAdded, _ := time.Parse(time.RFC3339, *vuln.DateAdded)

		desc := *vuln.ShortDescription

		// add reported exploitation references to the description
		if len(*vuln.VulncheckReportedExploitation) > 0 {
			desc += "<br><br>Reported Exploitation:<br>"
			for _, ref := range *vuln.VulncheckReportedExploitation {
				desc += fmt.Sprintf(" - %s<br>", *ref.Url)
			}
		}

		feedEntry := &feeds.Item{
			Title:       fmt.Sprintf("[vulncheck] %s", (*vuln.Cve)[0]),
			Link:        &feeds.Link{Href: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", (*vuln.Cve)[0])},
			Description: desc,
			Created:     dateAdded,
		}

		// tack on the vulnerable name if available
		if len(*vuln.VulnerabilityName) > 0 {
			feedEntry.Title += fmt.Sprintf(" - %s", *vuln.VulnerabilityName)
		}

		feed.Items = append(feed.Items, feedEntry)
	}

	fmt.Println(feed.ToRss())
}
