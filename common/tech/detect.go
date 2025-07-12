package tech

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/httpx"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type TechDetecter struct {
	FinerPrints map[string][]string // fp rules
	URIs        map[string][]string
}

func (t *TechDetecter) Init(rulePath string) (err error) {
	t.URIs = make(map[string][]string)
	t.FinerPrints = make(map[string][]string)
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
	// 去重uris
	for method, paths := range t.URIs {
		t.URIs[method] = sliceutil.Dedupe(paths)
	}
	// 注册一些函数
	var icontains = func(args ...interface{}) (interface{}, error) {
		return strings.Contains(strings.ToLower(toString(args[0])), strings.ToLower(toString(args[1]))), nil
	}
	dsl.DefaultHelperFunctions["icontains"] = icontains
	return nil
}
func (t *TechDetecter) ParseRule(filename string) error {
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
		for _, path := range line.Path {
			if path != "/" && path != "" {
				if line.Method == "" {
					line.Method = "GET"
				}
				t.URIs[line.Method] = append(t.URIs[line.Method], path)
			}
		}
		if line.DSL != "" {
			t.FinerPrints[matchers.Info.Product] = append(t.FinerPrints[matchers.Info.Product], line.DSL)
		}
	}
	return nil
}
func (t *TechDetecter) Detect(faviconMMH3 string, response *httpx.Response) ([]string, error) {
	products := make([]string, 0)
	tlsInfo, err := json.Marshal(response.TLSData)
	if err != nil {
		tlsInfo = []byte("")
	}
	data := map[string]interface{}{
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
	}

	var eg errgroup.Group
	eg.SetLimit(100)
	for product, rules := range t.FinerPrints {
		for _, rule := range rules {
			rule := rule // avoid closure capture
			eg.Go(func() error {
				compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(rule, dsl.DefaultHelperFunctions)
				if err != nil {
					gologger.Error().Msgf("failed to compile expression: %s product:%s", err, product)
					return nil
				}

				result, err := compiledExpression.Evaluate(data)
				if err != nil {
					gologger.Error().Msgf("failed to evaluate expression: %s product:%s", err, product)
					return nil
				}
				if result == true {
					products = append(products, product)
				}
				return nil
			})
		}
	}
	if err := eg.Wait(); err != nil {
		gologger.Error().Msgf(fmt.Sprintf("tech detect error:%s", err.Error()))
		return products, err
	}
	return sliceutil.Dedupe(products), nil

}

// toString converts an interface to string in a quick way
func toString(data interface{}) string {
	switch s := data.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case int32:
		return strconv.Itoa(int(s))
	case int16:
		return strconv.FormatInt(int64(s), 10)
	case int8:
		return strconv.FormatInt(int64(s), 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint16:
		return strconv.FormatUint(uint64(s), 10)
	case uint8:
		return strconv.FormatUint(uint64(s), 10)
	case []byte:
		return string(s)
	case fmt.Stringer:
		return s.String()
	case error:
		return s.Error()
	default:
		return fmt.Sprintf("%v", data)
	}
}
