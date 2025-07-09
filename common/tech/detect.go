package tech

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/tech/cel"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type TechDetecter struct {
	FinerPrints []FingerPrint
	URIs        map[string][]string
}

func (t *TechDetecter) Init(rulePath string) (err error) {
	t.URIs = make(map[string][]string)
	if !Exists(rulePath) {
		return os.ErrNotExist
	}
	if IsDir(rulePath) {
		files := ReadDir(rulePath)
		for _, file := range files {
			if filepath.Ext(file) != ".yml" && filepath.Ext(file) != ".yaml" {
				continue
			}
			err := t.ParseRule(file)
			if err != nil {
				gologger.Error().Msgf("file %s error:%s", file, err)
				continue
			}
		}
	} else {
		err := t.ParseRule(rulePath)
		if err != nil {
			gologger.Error().Msgf("file %s error:%s", rulePath, err)
		}
	}
	for method, fp := range t.FinerPrints {
		t.FinerPrints[method].Conditions = sliceutil.Dedupe(fp.Conditions)
	}
	return nil
}
func (t *TechDetecter) ParseRule(filename string) error {
	var fingerPrint = FingerPrint{}
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var matchers Matchers
	err = yaml.Unmarshal(content, &matchers)
	if err != nil {
		return err
	}
	for _, line := range matchers.Rules {
		if line.Path != "/" && line.Path != "" {
			if line.Method == "" {
				line.Method = "GET"
			}
			t.URIs[line.Method] = append(t.URIs[line.Method], line.Path)
		}
		if line.CEL != "" {
			fingerPrint.Conditions = append(fingerPrint.Conditions, line.CEL)
		}
	}
	data, err := json.Marshal(matchers.Info)
	if err != nil {
		return err
	}
	var info Info
	err = json.Unmarshal(data, &info)
	if err != nil {
		return err
	}
	fingerPrint.Name = info.Product
	t.FinerPrints = append(t.FinerPrints, fingerPrint)
	return nil
}
func (t *TechDetecter) Detect(faviconMMH3 string, response *httpx.Response) ([]string, error) {
	options := cel.InitCelOptions()
	env, err := cel.InitCelEnv(&options)
	if err != nil {
		return nil, err
	}
	var eg errgroup.Group
	eg.SetLimit(100)
	var product []string
	for _, r := range t.FinerPrints {
		r := r // avoid closure capture
		eg.Go(func() error {
			var matches string
			for i, match := range r.Conditions {
				if i < len(r.Conditions)-1 {
					matches = matches + "(" + match + ") || "
				} else {
					matches = matches + "(" + match + ")"
				}
			}
			ast, iss := env.Compile(matches)
			if iss.Err() != nil {
				gologger.Debug().Msgf(fmt.Sprintf("product: %s error:%s", r.Name, iss.Err().Error()))
				return err
			}
			prg, err := env.Program(ast)
			if err != nil {
				return err
			}
			tlsInfo, err := json.Marshal(response.TLSData)
			if err != nil {
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
				"favicon":     faviconMMH3,
			})
			if err != nil {
				return err
			}

			if out.(types.Bool) {
				product = append(product, strings.ToLower(r.Name))
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		gologger.Error().Msgf(fmt.Sprintf("tech detect error:%s", err.Error()))
		return product, err
	}
	return sliceutil.Dedupe(product), nil

}
