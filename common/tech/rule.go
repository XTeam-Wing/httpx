package tech

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Match string   `yaml:"matches"`
	Info  TechInfo `yaml:"info"`
}

func ParseYaml(filename string) (FingerPrint, error) {
	var fingerPrint = FingerPrint{}

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return fingerPrint, err
	}
	var rule Rule
	err = yaml.Unmarshal(content, &rule)
	if err != nil {
		return fingerPrint, err
	}

	slice := LinesToSlice(rule.Match)
	for _, line := range slice {
		if line != "" {
			fingerPrint.Matches = append(fingerPrint.Matches, line)
		}
	}
	data, err := json.Marshal(rule.Info)
	if err != nil {
		return fingerPrint, err
	}
	var info TechInfo
	err = json.Unmarshal(data, &info)
	if err != nil {
		return fingerPrint, err
	}
	fingerPrint.Infos = info.Product
	return fingerPrint, nil

}

func LinesToSlice(str string) []string {
	toSlice := strings.Split(str, "\n")
	return toSlice
}

func GetCerts(resp *http.Response) []byte {
	var certs []byte
	if resp.TLS != nil {
		cert := resp.TLS.PeerCertificates[0]
		var str string
		if js, err := json.Marshal(cert); err == nil {
			certs = js
		}
		str = string(certs) + cert.Issuer.String() + cert.Subject.String()
		certs = []byte(str)
	}
	return certs
}

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
