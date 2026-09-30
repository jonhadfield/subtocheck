package subtocheck

type processedIssues struct {
	potVulns []issue
	DNS      []issue
	request  []issue
}

func getIssuesSummary(issues issues) (pIssues processedIssues) {
	for _, issue := range issues {
		switch issue.kind {
		case "request":
			pIssues.request = append(pIssues.request, issue)
		case "dns":
			pIssues.DNS = append(pIssues.DNS, issue)
		case "vuln":
			pIssues.potVulns = append(pIssues.potVulns, issue)
		}
	}
	return
}
