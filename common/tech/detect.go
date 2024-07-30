package tech

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/tech/cel"
)

type TechDetecter struct {
	// Apps is organized as <name, fingerprint>
	FinerPrint []FingerPrint
}

func (t *TechDetecter) Init(rulePath string) error {
	if !Exists(rulePath) {
		return os.ErrNotExist
	}
	if IsDir(rulePath) {
		files := ReadDir(rulePath)
		for _, file := range files {
			if !strings.Contains(file, ".yaml") {
				continue
			}
			rule, err := ParseYaml(file)
			if err != nil {
				gologger.Error().Msgf(fmt.Sprintf("file %s error:%s", file, err))
				continue
			}
			t.FinerPrint = append(t.FinerPrint, rule)
		}
	} else {
		rule, err := ParseYaml(rulePath)
		if err != nil {
			gologger.Error().Msgf(fmt.Sprintf("file %s error:%s", rulePath, err))
		}
		t.FinerPrint = append(t.FinerPrint, rule)
	}
	return nil
}

func (t *TechDetecter) Detect(response *http.Response) (string, error) {
	options := cel.InitCelOptions()
	env, err := cel.InitCelEnv(&options)
	if err != nil {
		return "", err
	}
	body, _ := ioutil.ReadAll(response.Body)
	headerInfo := ""
	for k, v := range response.Header {
		headerInfo += fmt.Sprintf("%v: %v\n", k, v[0])
	}
	var product []string
	for _, r := range t.FinerPrint {
		var matches string

		for i, match := range r.Matches {
			if i < len(r.Matches)-1 {
				matches = matches + "(" + match + ") || "
			} else {
				matches = matches + "(" + match + ")"
			}
		}
		ast, iss := env.Compile(matches)
		if iss.Err() != nil {
			continue
		}
		prg, err := env.Program(ast)
		if err != nil {
			continue
		}
		out, _, err := prg.Eval(map[string]interface{}{
			"body":        string(body),
			"title":       GetTitle(string(body)),
			"header":      headerInfo,
			"server":      fmt.Sprintf("server: %v\n", response.Header["Server"]),
			"cert":        string(GetCerts(response)),
			"banner":      headerInfo,
			"protocol":    "",
			"port":        "",
			"status_code": response.StatusCode,
		})
		if err != nil {
			gologger.Error().Msgf(fmt.Sprintf("product: %s rule Eval error:%s", r.Infos, err.Error()))
			continue
		}

		if out.(types.Bool) {
			product = append(product, strings.ToLower(r.Infos))
		}
	}
	return SliceToSting(product), nil

}
