package tech

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/httpx/common/httpx"

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

func (t *TechDetecter) Detect(response *httpx.Response) (string, error) {
	options := cel.InitCelOptions()
	env, err := cel.InitCelEnv(&options)
	if err != nil {
		return "", err
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
			gologger.Debug().Msgf(fmt.Sprintf("product: %s rule Compile error:%s", r.Infos, iss.Err().Error()))
			continue
		}
		prg, err := env.Program(ast)
		if err != nil {
			gologger.Debug().Msgf(fmt.Sprintf("product: %s rule Program error:%s", r.Infos, err.Error()))
			continue
		}
		tlsInfo, err := json.Marshal(response.TLSData)
		if err != nil {
			gologger.Debug().Msgf(fmt.Sprintf("product: %s tlsData Marshal error:%s", r.Infos, err.Error()))
			tlsInfo = []byte("")
		}

		out, _, err := prg.Eval(map[string]interface{}{
			"body":        string(response.Data),
			"title":       httpx.ExtractTitle(response),
			"header":      response.RawHeaders,
			"server":      fmt.Sprintf("%v", strings.Join(response.Headers["Server"], ",")),
			"cert":        string(tlsInfo),
			"banner":      response.RawHeaders,
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
