package tech

import (
	"fmt"
	"regexp"
	"strings"
)



func LinesToSlice(str string) []string {
	toSlice := strings.Split(str, "\n")
	return toSlice
}

//func GetCerts(resp *http.Response) []byte {
//	var certs []byte
//	if resp.TLS != nil {
//		cert := resp.TLS.PeerCertificates[0]
//		var str string
//		if js, err := json.Marshal(cert); err == nil {
//			certs = js
//		}
//		str = string(certs) + cert.Issuer.String() + cert.Subject.String()
//		certs = []byte(str)
//	}
//	return certs
//}

func GetTitle(content string) string {
	reTitle := regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
	matchResults := reTitle.FindAllString(content, -1)
	var nilString = ""
	var matches = []string{"<title>", "</title>"}
	return StringReplace(SliceToSting(matchResults), matches, nilString)
}

func StringReplace(old string, matches []string, new string) string {
	for _, math := range matches {
		old = strings.Replace(old, math, new, -1)
	}
	return old
}
func SliceToSting(slice []string) string {
	toString := fmt.Sprintf(strings.Join(slice, ","))
	return toString
}
