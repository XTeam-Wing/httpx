package tech

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/embed"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"gopkg.in/yaml.v3"
)

// TechRule 技术检测规则
type TechRule struct {
	Method string   `yaml:"method"`
	Path   []string `yaml:"path"`
	DSL    string   `yaml:"dsl"`
}

type TechDetecter struct {
	// 重新设计的规则存储结构
	ProductRules map[string][]TechRule // 产品名 -> 规则列表
	URIs         map[string][]string   // 方法 -> 路径列表（保持兼容性）
	// 预编译的表达式缓存：产品名 -> 规则索引 -> 编译后的表达式
	compiledExpressions map[string][]*CompiledRule
	compiledMutex       sync.RWMutex
	matchedProduct      map[string][]string // 已经匹配的产品
	matchedMutex        sync.RWMutex        // 保护 matchedProduct 的读写锁
}

// CompiledRule 编译后的规则
type CompiledRule struct {
	Method     string                         `json:"method"`
	Paths      []string                       `json:"paths"`
	Expression *govaluate.EvaluableExpression `json:"-"`
	RawDSL     string                         `json:"raw_dsl"`
}

// Add MatchedProduct 添加已匹配的产品
func (t *TechDetecter) AddMatchedProduct(target string, product []string) {
	t.matchedMutex.Lock()
	defer t.matchedMutex.Unlock()
	t.matchedProduct[target] = append(t.matchedProduct[target], product...)
}

// isProductMatched 线程安全地检查产品是否已匹配
func (t *TechDetecter) isProductMatched(target, product string) bool {
	t.matchedMutex.RLock()
	defer t.matchedMutex.RUnlock()
	return sliceutil.Contains(t.matchedProduct[target], product)
}

func (t *TechDetecter) Init(rulePath string) (err error) {
	t.URIs = make(map[string][]string)
	t.ProductRules = make(map[string][]TechRule)
	t.matchedProduct = make(map[string][]string) // 初始化已匹配的产品
	t.compiledExpressions = make(map[string][]*CompiledRule)

	// 使用内置规则初始化
	userDefinedPath := "data/fp"
	files, err := embed.AssetDir(userDefinedPath)
	if err != nil {
		return errors.New("user defined rules is missed: " + err.Error())
	}
	fmt.Println("user defined rules:", userDefinedPath, len(files))
	for _, fileName := range files {
		absFileName := path.Join(userDefinedPath, fileName)
		content, err := embed.Asset(absFileName)
		if err != nil {
			continue
		}
		err = t.ParseRule(content)
		if err != nil {
			gologger.Error().Msgf("file %s error:%s", absFileName, err)
			continue
		}
	}
	if !Exists(rulePath) {
		return nil
	}
	if IsDir(rulePath) {
		files := ReadDir(rulePath)
		for _, file := range files {
			content, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			err = t.ParseRule(content)
			if err != nil {
				gologger.Error().Msgf("file %s error:%s", file, err)
				continue
			}
		}
	} else {
		content, err := os.ReadFile(rulePath)
		if err != nil {
			return err
		}
		err = t.ParseRule(content)
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

func (t *TechDetecter) ParseRule(content []byte) error {
	var matcher Matchers

	err := yaml.Unmarshal(content, &matcher)
	if err != nil {
		return err
	}

	productName := matcher.Info.Product
	for _, line := range matcher.Rules {
		// 跳过没有DSL的规则
		if line.DSL == "" {
			continue
		}

		// 转换Rule为TechRule
		techRule := TechRule(line)

		// 如果方法为空，默认为GET
		if techRule.Method == "" {
			techRule.Method = "GET"
		}

		// 添加到产品规则中 - 每个Rule对应一个独立的TechRule
		t.ProductRules[productName] = append(t.ProductRules[productName], techRule)

		// 保持URI兼容性（用于获取所有需要请求的路径）
		for _, path := range line.Path {
			if path != "/" && path != "" {
				t.URIs[techRule.Method] = append(t.URIs[techRule.Method], path)
			}
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

	// 遍历新的产品规则结构
	for product, techRules := range t.ProductRules {
		compiledRules := make([]*CompiledRule, 0, len(techRules))
		for _, rule := range techRules {
			if rule.DSL == "" {
				continue // 跳过空的DSL规则
			}

			expr, err := govaluate.NewEvaluableExpressionWithFunctions(rule.DSL, localHelperFunctions)
			if err != nil {
				gologger.Error().Msgf("failed to precompile expression for product %s: %s", product, err)
				continue
			}

			compiledRule := &CompiledRule{
				Method:     rule.Method,
				Paths:      rule.Path,
				Expression: expr,
				RawDSL:     rule.DSL,
			}
			compiledRules = append(compiledRules, compiledRule)
		}
		t.compiledExpressions[product] = compiledRules
	}
}

// getCompiledExpressions 线程安全地获取编译后的表达式
func (t *TechDetecter) getCompiledExpressions(product string) []*CompiledRule {
	t.compiledMutex.RLock()
	defer t.compiledMutex.RUnlock()
	return t.compiledExpressions[product]
}

func (t *TechDetecter) Detect(inputURL, requestPath, requestMethod, faviconMMH3 string, response *httpx.Response) ([]string, error) {
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

	// 如果请求方法为空，默认为GET
	if requestMethod == "" {
		requestMethod = "GET"
	}

	var detectedProducts sync.Map

	// var eg errgroup.Group
	// eg.SetLimit(100)

	// 获取所有产品名称（线程安全）
	t.compiledMutex.RLock()
	productNames := make([]string, 0, len(t.ProductRules))
	for product := range t.ProductRules {
		productNames = append(productNames, product)
	}
	t.compiledMutex.RUnlock()

	// 遍历所有产品规则
	for _, product := range productNames {
		if t.isProductMatched(inputURL, product) {
			continue
		}
		product := product // capture product variable

		// eg.Go(func() error {
		// 在 goroutine 内部检查是否已经检测到该产品
		if _, exists := detectedProducts.Load(product); exists {
			continue
		}

		// 在 goroutine 内部获取编译后的规则，避免变量捕获问题
		compiledRules := t.getCompiledExpressions(product)
		if len(compiledRules) == 0 {
			continue
		}

		// 对于每个产品，检查其编译后的规则
		for _, compiledRule := range compiledRules {
			if compiledRule == nil || compiledRule.Expression == nil {
				continue
			}

			// 检查当前请求的方法和路径是否匹配规则
			if !t.pathMatches(requestPath, requestMethod, compiledRule) {
				continue // 路径或方法不匹配，跳过此规则
			}

			result, err := compiledRule.Expression.Evaluate(data)
			if err != nil {
				gologger.Error().Msgf("failed to evaluate expression for product:%s", product)
				continue
			}
			if result == true {
				// 使用 LoadOrStore 确保只有第一个成功的 goroutine 存储结果
				if _, loaded := detectedProducts.LoadOrStore(product, true); !loaded {
					gologger.Debug().Msgf("tech detect success, product:%s, url:%s, path:%s, method:%s",
						product, inputURL, requestPath, requestMethod)
				}
				break
			}
		}

		// })
	}

	// if err := eg.Wait(); err != nil {
	// 	gologger.Error().Msgf("tech detect error:%s", err.Error())
	// }

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

// pathMatches 检查当前请求的路径和方法是否匹配规则
func (t *TechDetecter) pathMatches(requestPath, requestMethod string, rule *CompiledRule) bool {
	// 检查方法是否匹配
	if rule.Method != "" && !strings.EqualFold(rule.Method, requestMethod) {
		return false
	}
	if len(rule.Paths) == 0 {
		if requestPath == "" || requestPath == "/" {
			// 如果规则没有指定路径且请求路径是根路径或空路径，则匹配
			return true
		}
		if requestPath != "" && requestPath != "/" {
			// 如果规则没有指定路径且请求路径不是根路径或空路径，则不匹配
			return false
		}
	}
	// 检查路径是否严格匹配
	for _, rulePath := range rule.Paths {
		// 严格匹配路径，不允许模糊匹配
		if requestPath == rulePath {
			return true
		}
		// 特殊情况：如果规则路径是 "/" 或空，匹配根路径请求
		if (rulePath == "/" || rulePath == "") && (requestPath == "/" || requestPath == "") {
			return true
		}
	}

	return false
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
