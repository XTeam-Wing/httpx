// Package tech 提供HTTP指纹识别功能
//
// 支持两种规则格式:
//   - DSL规则: 使用govaluate表达式语法
//   - Nuclei规则: 兼容nuclei模板格式
//
// 使用示例:
//
//	detector, err := tech.NewDetector("rules/", true)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	products, err := detector.Detect(url, "/", "GET", faviconHash, response)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, p := range products {
//	    fmt.Println("Detected:", p)
//	}
package tech

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/embed"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"gopkg.in/yaml.v3"
)

// Detector 指纹检测器
type Detector struct {
	useInternal bool

	store       *RuleStore
	matchedOnce sync.Map // target -> *sync.Map[product]bool
}

// RuleStore 规则存储器
type RuleStore struct {
	dslRules    map[string][]*CompiledRule       // 产品名 -> DSL规则列表
	nucleiRules map[string][]*CompiledNucleiRule // 产品名 -> Nuclei规则列表
	mu          sync.RWMutex
}

// CompiledRule DSL编译后的规则
type CompiledRule struct {
	Method     string
	Paths      []string
	Expression *govaluate.EvaluableExpression
}

// CompiledNucleiRule Nuclei编译后的规则
type CompiledNucleiRule struct {
	Method     string
	Paths      []string
	Expression *operators.Operators
}

// NewDetector 创建新的检测器
func NewDetector(rulePath string, useInternal bool) (*Detector, error) {
	d := &Detector{
		useInternal: useInternal,
		store: &RuleStore{
			dslRules:    make(map[string][]*CompiledRule),
			nucleiRules: make(map[string][]*CompiledNucleiRule),
		},
	}

	if err := d.loadRules(rulePath); err != nil {
		return nil, err
	}

	return d, nil
}

// loadRules 加载规则
func (d *Detector) loadRules(rulePath string) error {
	parser := newRuleParser(d.store)

	// 加载内置规则
	if d.useInternal {
		if err := d.loadInternalRules(parser); err != nil {
			return err
		}
	}

	// 加载外部规则
	if err := d.loadExternalRules(parser, rulePath); err != nil {
		return err
	}

	// 编译所有DSL规则
	parser.compileAllDSLRules()

	return nil
}

// loadInternalRules 加载内置规则
func (d *Detector) loadInternalRules(parser *ruleParser) error {
	fpDir := "data/fp"
	files, err := embed.AssetDir(fpDir)
	if err != nil {
		return errors.New("internal rules directory not found: " + err.Error())
	}

	for _, fileName := range files {
		content, err := embed.Asset(path.Join(fpDir, fileName))
		if err != nil {
			continue
		}
		if err := parser.parseDSLRule(content); err != nil {
			gologger.Error().Msgf("parse internal rule %s: %s", fileName, err)
		}
	}

	return nil
}

// loadExternalRules 加载外部规则
func (d *Detector) loadExternalRules(parser *ruleParser, rulePath string) error {
	if rulePath == "" {
		return nil
	}

	if isDir(rulePath) {
		for _, file := range readDir(rulePath) {
			content, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			d.parseRuleFile(parser, file, content)
		}
	} else if exists(rulePath) {
		content, err := os.ReadFile(rulePath)
		if err != nil {
			return err
		}
		d.parseRuleFile(parser, rulePath, content)
	}

	return nil
}

// parseRuleFile 解析规则文件（自动识别格式）
func (d *Detector) parseRuleFile(parser *ruleParser, filename string, content []byte) {
	// 先尝试DSL格式
	if err := parser.parseDSLRule(content); err != nil {
		// 再尝试Nuclei格式
		if err := parser.parseNucleiRule(content); err != nil {
			gologger.Warning().Msgf("parse rule file %s: %s", filename, err)
		}
	}
}

// Detect 使用DSL规则检测指纹
func (d *Detector) Detect(inputURL, reqPath, reqMethod, faviconHash string, resp *httpx.Response) ([]string, error) {
	data := d.buildDSLContext(resp, faviconHash)
	reqMethod = normalizeMethod(reqMethod)

	return d.matchDSLRules(inputURL, reqPath, reqMethod, data)
}

// DetectWithNuclei 使用Nuclei规则检测指纹
func (d *Detector) DetectWithNuclei(inputURL, reqPath, reqMethod, favicon string, resp *httpx.Response) ([]string, error) {
	dslMap := responseToDSLMap(resp, "", inputURL, "", "", string(resp.Data), resp.RawHeaders, favicon, 0, nil)
	reqMethod = normalizeMethod(reqMethod)

	return d.matchNucleiRules(inputURL, reqPath, reqMethod, dslMap)
}

// AddMatchedProduct 标记产品已匹配（避免重复检测）
func (d *Detector) AddMatchedProduct(target string, products []string) {
	matched, _ := d.matchedOnce.LoadOrStore(target, &sync.Map{})
	productMap := matched.(*sync.Map)
	for _, p := range products {
		productMap.Store(p, true)
	}
}

// isProductMatched 检查产品是否已匹配
func (d *Detector) isProductMatched(target, product string) bool {
	matched, ok := d.matchedOnce.Load(target)
	if !ok {
		return false
	}
	_, exists := matched.(*sync.Map).Load(product)
	return exists
}

// buildDSLContext 构建DSL表达式上下文
func (d *Detector) buildDSLContext(resp *httpx.Response, faviconHash string) map[string]interface{} {
	tlsInfo, _ := json.Marshal(resp.TLSData)

	return map[string]interface{}{
		"body":        string(resp.Data),
		"title":       httpx.ExtractTitle(resp),
		"header":      resp.RawHeaders,
		"server":      strings.Join(resp.Headers["Server"], ","),
		"cert":        string(tlsInfo),
		"banner":      resp.RawHeaders,
		"protocol":    "",
		"port":        "",
		"status_code": resp.StatusCode,
		"favicon":     faviconHash,
	}
}

// matchDSLRules 匹配DSL规则
func (d *Detector) matchDSLRules(target, reqPath, reqMethod string, data map[string]interface{}) ([]string, error) {
	d.store.mu.RLock()
	defer d.store.mu.RUnlock()

	var results sync.Map

	for product, rules := range d.store.dslRules {
		if d.isProductMatched(target, product) {
			continue
		}

		for _, rule := range rules {
			if rule == nil || rule.Expression == nil {
				continue
			}

			if !matchPath(reqPath, reqMethod, rule.Method, rule.Paths) {
				continue
			}

			result, err := rule.Expression.Evaluate(data)
			if err != nil {
				gologger.Error().Msgf("evaluate DSL for %s: %s", product, err)
				continue
			}

			if result == true {
				results.Store(product, true)
				break // 一个产品匹配成功即可
			}
		}
	}

	return collectResults(&results), nil
}

// matchNucleiRules 匹配Nuclei规则
func (d *Detector) matchNucleiRules(target, reqPath, reqMethod string, data map[string]interface{}) ([]string, error) {
	d.store.mu.RLock()
	defer d.store.mu.RUnlock()

	var results sync.Map

	for product, rules := range d.store.nucleiRules {
		if d.isProductMatched(target, product) {
			continue
		}

		for _, rule := range rules {
			if rule == nil || rule.Expression == nil {
				continue
			}

			if !matchPath(reqPath, reqMethod, rule.Method, rule.Paths) {
				continue
			}

			if d.matchNucleiExpression(rule.Expression, data) {
				results.Store(product, true)
				break
			}
		}
	}

	return collectResults(&results), nil
}

// matchNucleiExpression 匹配Nuclei表达式
func (d *Detector) matchNucleiExpression(expr *operators.Operators, data map[string]interface{}) bool {
	for _, matcher := range expr.Matchers {
		if matcher == nil {
			continue
		}
		if matched, _ := d.matchSingle(data, matcher); matched {
			return true
		}
	}
	return false
}

// matchSingle 单个matcher匹配
func (d *Detector) matchSingle(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	item, ok := d.getMatchPart(matcher.Part, data)
	if !ok && matcher.Type.MatcherType != matchers.DSLMatcher {
		return false, nil
	}

	switch matcher.GetType() {
	case matchers.FaviconMatcher:
		return d.matchFavicon(data, matcher)
	case matchers.StatusMatcher:
		return d.matchStatusCode(data, matcher)
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(item))), nil
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(item, data))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(item))
	case matchers.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(item))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data)), nil
	case matchers.XPathMatcher:
		return matcher.Result(matcher.MatchXPath(item)), nil
	}
	return false, nil
}

func (d *Detector) matchFavicon(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	hash, ok := data["favicon"].(string)
	if !ok || len(matcher.Hash) == 0 {
		return false, nil
	}
	return sliceutil.Contains(matcher.Hash, hash), nil
}

func (d *Detector) matchStatusCode(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	statusCode, ok := data["status_code"].(int)
	if !ok {
		return false, nil
	}
	respStr, _ := data["response"].(string)
	return matcher.Result(matcher.MatchStatusCode(statusCode)),
		[]string{responsehighlighter.CreateStatusCodeSnippet(respStr, statusCode)}
}

// getMatchPart 获取匹配部分
func (d *Detector) getMatchPart(part string, data map[string]interface{}) (string, bool) {
	switch part {
	case "", "body":
		part = "body"
	case "header":
		part = "all_headers"
	case "all":
		return types.ToString(data["body"]) + types.ToString(data["all_headers"]), true
	}

	item, ok := data[part]
	if !ok {
		return "", false
	}
	return types.ToString(item), true
}

// Extract 提取信息
func (d *Detector) Extract(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	item, ok := d.getMatchPart(extractor.Part, data)
	if !ok && !extractors.SupportsMap(extractor) {
		return nil
	}

	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(item)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	case extractors.XPathExtractor:
		return extractor.ExtractXPath(item)
	case extractors.JSONExtractor:
		return extractor.ExtractJSON(item)
	case extractors.DSLExtractor:
		return extractor.ExtractDSL(data)
	}
	return nil
}

// GetAllPaths 获取所有需要探测的路径规则
func (d *Detector) GetAllPaths() []PathRule {
	d.store.mu.RLock()
	defer d.store.mu.RUnlock()

	var paths []PathRule
	seen := make(map[string]struct{})

	// 收集DSL规则中的路径
	for _, rules := range d.store.dslRules {
		for _, rule := range rules {
			for _, p := range rule.Paths {
				if p == "" {
					p = "/"
				}
				key := rule.Method + ":" + p
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					paths = append(paths, PathRule{
						Method: rule.Method,
						Path:   p,
					})
				}
			}
		}
	}

	// 收集Nuclei规则中的路径
	for _, rules := range d.store.nucleiRules {
		for _, rule := range rules {
			for _, p := range rule.Paths {
				if p == "" {
					p = "/"
				}
				key := rule.Method + ":" + p
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					paths = append(paths, PathRule{
						Method: rule.Method,
						Path:   p,
					})
				}
			}
		}
	}

	return paths
}

// PathRule 路径规则
type PathRule struct {
	Method   string
	Path     string
	Headers  map[string]string
	Redirect bool
}

// ============================================================================
// 辅助函数
// ============================================================================

// matchPath 检查路径和方法是否匹配
func matchPath(reqPath, reqMethod, ruleMethod string, rulePaths []string) bool {
	// 检查方法
	if ruleMethod != "" && !strings.EqualFold(ruleMethod, reqMethod) {
		return false
	}

	// 检查路径
	if len(rulePaths) == 0 {
		return isRootPath(reqPath)
	}

	for _, p := range rulePaths {
		if reqPath == p {
			return true
		}
		if isRootPath(p) && isRootPath(reqPath) {
			return true
		}
	}
	return false
}

func isRootPath(p string) bool {
	return p == "" || p == "/"
}

func normalizeMethod(method string) string {
	if method == "" {
		return "GET"
	}
	return method
}

func collectResults(m *sync.Map) []string {
	var results []string
	m.Range(func(key, _ interface{}) bool {
		if product, ok := key.(string); ok {
			results = append(results, product)
		}
		return true
	})
	return sliceutil.Dedupe(results)
}

func toString(data interface{}) string {
	switch v := data.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	case fmt.Stringer:
		return v.String()
	case error:
		return v.Error()
	default:
		return fmt.Sprintf("%v", data)
	}
}

// ============================================================================
// 兼容旧API (Deprecated)
// ============================================================================

// TechDetecter 旧版检测器
// Deprecated: 请使用 Detector
type TechDetecter struct {
	detector *Detector
	Rules    map[string][]Rule // 暴露规则供外部访问
}

// Init 初始化检测器
// Deprecated: 请使用 NewDetector
func (t *TechDetecter) Init(rulePath string, useInternal bool) error {
	d, err := NewDetector(rulePath, useInternal)
	if err != nil {
		return err
	}
	t.detector = d

	// 从解析器获取原始规则
	t.Rules = make(map[string][]Rule)
	parser := newRuleParser(d.store)

	// 加载内置规则
	if useInternal {
		fpDir := "data/fp"
		files, _ := embed.AssetDir(fpDir)
		for _, fileName := range files {
			content, err := embed.Asset(path.Join(fpDir, fileName))
			if err != nil {
				continue
			}
			t.loadRulesFromContent(content)
		}
	}

	// 加载外部规则
	if rulePath != "" {
		if isDir(rulePath) {
			for _, file := range readDir(rulePath) {
				content, err := os.ReadFile(file)
				if err != nil {
					continue
				}
				t.loadRulesFromContent(content)
			}
		} else if exists(rulePath) {
			content, _ := os.ReadFile(rulePath)
			t.loadRulesFromContent(content)
		}
	}

	_ = parser // 消除未使用的警告
	return nil
}

// loadRulesFromContent 从内容加载规则
func (t *TechDetecter) loadRulesFromContent(content []byte) {
	var m Matchers
	if err := yaml.Unmarshal(content, &m); err != nil {
		return
	}
	product := m.Info.Product
	if product == "" {
		return
	}
	for _, rule := range m.Rules {
		if rule.DSL == "" {
			continue
		}
		if len(rule.Path) == 0 {
			rule.Path = []string{"/"}
		}
		t.Rules[product] = append(t.Rules[product], rule)
	}
}

// AddMatchedProduct 添加已匹配的产品
// Deprecated: 请使用 Detector.AddMatchedProduct
func (t *TechDetecter) AddMatchedProduct(target string, products []string) {
	t.detector.AddMatchedProduct(target, products)
}

// Detect DSL规则检测
// Deprecated: 请使用 Detector.Detect
func (t *TechDetecter) Detect(inputURL, requestPath, requestMethod, faviconMMH3 string, response *httpx.Response) ([]string, error) {
	return t.detector.Detect(inputURL, requestPath, requestMethod, faviconMMH3, response)
}

// FingerHubDetect Nuclei规则检测
// Deprecated: 请使用 Detector.DetectWithNuclei
func (t *TechDetecter) FingerHubDetect(inputURL, requestPath, requestMethod, favicon string, response *httpx.Response) ([]string, error) {
	return t.detector.DetectWithNuclei(inputURL, requestPath, requestMethod, favicon, response)
}

func (t *TechDetecter) GetAllPaths() []PathRule {
	return t.detector.GetAllPaths()
}
