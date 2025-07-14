package tech

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

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
	// 预编译的表达式缓存
	compiledExpressions map[string][]*govaluate.EvaluableExpression
	compiledMutex       sync.RWMutex
	matchedProduct      map[string][]string // 已经匹配的产品
}

// Add MatchedProduct 添加已匹配的产品
func (t *TechDetecter) AddMatchedProduct(target string, product []string) {
	t.compiledMutex.Lock()
	defer t.compiledMutex.Unlock()
	t.matchedProduct[target] = append(t.matchedProduct[target], product...)
}
func (t *TechDetecter) Init(rulePath string) (err error) {
	t.URIs = make(map[string][]string)
	t.FinerPrints = make(map[string][]string)
	t.matchedProduct = make(map[string][]string) // 初始化已匹配的产品
	t.compiledExpressions = make(map[string][]*govaluate.EvaluableExpression)

	if !Exists(rulePath) {
		return os.ErrNotExist
	}
	if IsDir(rulePath) {
		files := ReadDir(rulePath)
		for _, file := range files {
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

	// 预编译所有表达式（在这里注册自定义函数，而不是修改全局map）
	t.precompileExpressions()
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

// precompileExpressions 预编译所有表达式以提高性能并减少并发问题
func (t *TechDetecter) precompileExpressions() {
	t.compiledMutex.Lock()
	defer t.compiledMutex.Unlock()

	// 创建本地的 helper functions 副本，避免并发访问全局 map
	localHelperFunctions := make(map[string]govaluate.ExpressionFunction)

	// 复制 DSL 默认函数
	for name, fn := range dsl.DefaultHelperFunctions {
		localHelperFunctions[name] = fn
	}

	// 添加自定义函数
	var icontains = func(args ...interface{}) (interface{}, error) {
		return strings.Contains(strings.ToLower(toString(args[0])), strings.ToLower(toString(args[1]))), nil
	}
	localHelperFunctions["icontains"] = icontains

	for product, rules := range t.FinerPrints {
		compiledRules := make([]*govaluate.EvaluableExpression, 0, len(rules))
		for _, rule := range rules {
			expr, err := govaluate.NewEvaluableExpressionWithFunctions(rule, localHelperFunctions)
			if err != nil {
				gologger.Error().Msgf("failed to precompile expression for product %s: %s", product, err)
				continue
			}
			compiledRules = append(compiledRules, expr)
		}
		t.compiledExpressions[product] = compiledRules
	}
}

// getCompiledExpressions 线程安全地获取编译后的表达式
func (t *TechDetecter) getCompiledExpressions(product string) []*govaluate.EvaluableExpression {
	t.compiledMutex.RLock()
	defer t.compiledMutex.RUnlock()
	return t.compiledExpressions[product]
}

func (t *TechDetecter) Detect(inputURL, faviconMMH3 string, response *httpx.Response) ([]string, error) {
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

	var detectedProducts sync.Map

	var eg errgroup.Group
	eg.SetLimit(100)

	for product := range t.FinerPrints {
		if sliceutil.Contains(t.matchedProduct[inputURL], product) {
			continue
		}
		product := product
		compiledExprs := t.getCompiledExpressions(product)

		if len(compiledExprs) == 0 {
			continue
		}

		eg.Go(func() error {
			if _, exists := detectedProducts.Load(product); exists {
				return nil
			}

			// 对于每个产品，顺序检查其表达式
			for _, expr := range compiledExprs {
				// 添加 nil 检查
				if expr == nil {
					continue
				}

				result, err := expr.Evaluate(data)
				if err != nil {
					gologger.Error().Msgf("failed to evaluate expression for product:%s, error:%s", product, err)
					continue
				}
				if result == true {
					// gologger.Debug().Msgf("tech detect success, product:%s, url:%s data:%v expr:%s", product, inputURL, data, expr.String())
					detectedProducts.Store(product, true)
					break
				}
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		gologger.Error().Msgf("tech detect error:%s", err.Error())
	}

	// 收集结果
	var products []string
	detectedProducts.Range(func(key, value interface{}) bool {
		if product, ok := key.(string); ok {
			products = append(products, product)
		}
		return true
	})

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
