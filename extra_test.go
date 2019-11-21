package whois

import (
	"fmt"
	"log"
	"testing"
)

func TestParseExpiryDate(t *testing.T) {
	var domains = []string{"qq.com", "qq.cn", "qq.ru", "qq.dev"}
	for _, domain := range domains {
		whois, e := GetWhois(domain)
		if e != nil {
			log.Fatal(e)
		}
		if len(whois) < 1 {
			log.Fatal(fmt.Errorf("Domain(%s) GetWhois is wrong", domain))
		}
		t := ParseExpiryDate(whois)
		if t.IsZero() {
			log.Fatal(fmt.Errorf("Domain(%s) ParseExpiryDate is wrong", domain))
		}
	}
}
