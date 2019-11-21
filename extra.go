// -------------------------
//
// Copyright 2015, undiabler
//
// git: github.com/undiabler/golang-whois
//
// http://undiabler.com
//
// Released under the Apache License, Version 2.0
//
//--------------------------

package whois

import (
	"regexp"
	"strings"
	"time"
)

func parser(re *regexp.Regexp, group int, data string) (result []string) {

	found := re.FindAllStringSubmatch(data, -1)

	if len(found) > 0 {
		for _, one := range found {
			if len(one) >= 2 && len(one[group]) > 0 {

				result = appendIfMissing(result, one[group])

			}
		}
	}

	return
}

//ParseNameServers func
//Parse uniq name servers from whois
func ParseNameServers(whois string) []string {

	return parser(regexp.MustCompile(`(?i)Name Server:\s+(.*?)(\s|$)`), 1, whois)

}

//ParseDomainStatus func
//Parse uniq domain status(codes) from whois
func ParseDomainStatus(whois string) []string {

	return parser(regexp.MustCompile(`(?i)(Domain )?Status:\s+(.*?)(\s|$)`), 2, whois)

}

//ParseExpiryDate func
func ParseExpiryDate(whois string) time.Time {
	expiryDates := parser(regexp.MustCompile(`(?i)(Registry Expiry Date|Expiration Time|paid-till):[ ]+(\d+\-\d+\-\d+[a-zA-Z ]?\d+:\d+:\d+[a-zA-Z ]?)`), 2, whois)
	for _, v := range expiryDates {
		var layout = ""
		s := strings.ToUpper(v)
		if strings.Contains(s, "T") && strings.Contains(s, "Z") {
			layout = time.RFC3339
		} else {
			layout = "2006-01-02 15:04:05"
		}
		t, e := time.Parse(layout, s)
		if e == nil {
			return t.In(time.Local)
		}
	}
	return time.Time{}
}

func appendIfMissing(slice []string, i string) []string {

	i = strings.ToLower(i)

	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}

	return append(slice, i)

}
