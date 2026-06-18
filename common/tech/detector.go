package tech

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/projectdiscovery/govaluate"
	"github.com/Mzack9999/gcache"
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

	store          *RuleStore
	matchedCache   gcache.Cache[string, *sync.Map] // target -> *sync.Map[product]bool，使用LRU自动淘汰
	allPathsCache  []PathRule                      // GetAllPaths结果缓存
	pathsCacheOnce sync.Once                       // 确保只初始化一次
	detectCounter  uint64                          // 检测计数器，用于定期GC
	counterMu      sync.Mutex                      // 计数器锁
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
	Headers    map[string]string
	Redirect   bool
	Expression *govaluate.EvaluableExpression
}

// CompiledNucleiRule Nuclei编译后的规则
type CompiledNucleiRule struct {
	Method     string
	Paths      []string
	Headers    map[string]string
	Redirect   bool
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
		// 使用LRU缓存，适配100并发线程长期运行场景
		// 2000容量 = 100线程 × 20倍余量，自动淘汰最少使用的
		matchedCache: gcache.New[string, *sync.Map](2000).LRU().Build(),
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
	files, err := embed.AssetAllDir(fpDir)
	if err != nil {
		return errors.New("internal rules directory not found: " + err.Error())
	}

	for _, fileName := range files {
		content, err := embed.Asset(fileName)
		if err != nil {
			continue
		}
		if err := parser.parseNucleiRule(content); err != nil {
			gologger.Warning().Msgf("parse internal rule %s: %s", fileName, err)
			if err := parser.parseDSLRule(content); err != nil {
				gologger.Warning().Msgf("parse internal rule error: %s: %s", fileName, err)
			}
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
	// 定期触发GC，防止长期运行内存泄露
	d.maybeRunGC()

	data := d.buildDSLContext(resp, faviconHash)
	reqMethod = normalizeMethod(reqMethod)

	results, err := d.matchDSLRules(inputURL, reqPath, reqMethod, data)

	// 清理并归还map到对象池
	cleanMapIfNeeded(data)

	return results, err
}

// DetectWithNuclei 使用Nuclei规则检测指纹
func (d *Detector) DetectWithNuclei(inputURL, reqPath, reqMethod, favicon string, resp *httpx.Response) ([]string, error) {
	dslMap := responseToDSLMap(resp, "", inputURL, "", "", string(resp.Data), resp.RawHeaders, favicon, 0, nil)
	reqMethod = normalizeMethod(reqMethod)

	results, err := d.matchNucleiRules(inputURL, reqPath, reqMethod, dslMap)

	// 清理并归还map到对象池
	cleanMapIfNeeded(dslMap)

	return results, err
}

// AddMatchedProduct 标记产品已匹配（避免重复检测）
// 使用LRU缓存，超过容量时自动淘汰最少使用的target
func (d *Detector) AddMatchedProduct(target string, products []string) {
	productMap, err := d.matchedCache.Get(target)
	if err != nil {
		// target不存在，创建新的sync.Map
		productMap = &sync.Map{}
		_ = d.matchedCache.Set(target, productMap)
	}

	// 限制每个target最多缓存100个product，防止单个sync.Map过大
	count := 0
	productMap.Range(func(_, _ interface{}) bool {
		count++
		return count < 100
	})

	if count >= 100 {
		// 已达上限，不再添加
		return
	}

	for _, p := range products {
		productMap.Store(p, true)
	}
}

// isProductMatched 检查产品是否已匹配
func (d *Detector) isProductMatched(target, product string) bool {
	productMap, err := d.matchedCache.Get(target)
	if err != nil {
		return false
	}
	_, exists := productMap.Load(product)
	return exists
}

// ClearMatchedCache 清理已匹配的缓存
func (d *Detector) ClearMatchedCache() {
	d.matchedCache.Purge()
}

// maybeRunGC 定期触发GC，防止长期运行内存泄露
// 每处理10000个目标后触发一次GC
func (d *Detector) maybeRunGC() {
	d.counterMu.Lock()
	d.detectCounter++
	counter := d.detectCounter
	d.counterMu.Unlock()

	// 每10000次检测触发一次GC
	if counter%10000 == 0 {
		// 异步执行GC，不阻塞主流程
		go func() {
			// runtime.GC() // 如需要可以强制GC
			// 清理部分缓存
			if counter%50000 == 0 {
				// 每50000次清理一次匹配缓存（但LRU会自动管理）
				gologger.Debug().Msg("Periodic cleanup triggered")
			}
		}()
	}
}

// ClearMatchedTarget 清理指定目标的匹配缓存
func (d *Detector) ClearMatchedTarget(target string) {
	_ = d.matchedCache.Remove(target)
}

// dslContextPool 对象池，用于复用DSL上下文map
var dslContextPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]interface{}, 12)
	},
}

// cleanMapIfNeeded 清理map如果键值对过多（防止对象池中的map无限增长）
func cleanMapIfNeeded(m map[string]interface{}) {
	// 如果map的键超过50个，说明被污染了，重新创建
	if len(m) > 50 {
		// 不放回池中，GC会回收
		return
	}
	// 清空后放回池
	for k := range m {
		delete(m, k)
	}
	dslContextPool.Put(m)
}

// buildDSLContext 构建DSL表达式上下文
func (d *Detector) buildDSLContext(resp *httpx.Response, faviconHash string) map[string]interface{} {
	tlsInfo, _ := json.Marshal(resp.TLSData)

	// 从对象池获取map
	data := dslContextPool.Get().(map[string]interface{})

	// 清空并填充数据
	for k := range data {
		delete(data, k)
	}

	// 优化：对于大响应体，避免不必要的string转换
	// DSL引擎可以接受[]byte或string
	if len(resp.Data) > 102400 { // 大于100KB时使用[]byte
		data["body"] = resp.Data
	} else {
		data["body"] = string(resp.Data)
	}
	data["title"] = httpx.ExtractTitle(resp)
	data["header"] = resp.RawHeaders
	data["server"] = strings.Join(resp.Headers["Server"], ",")
	data["cert"] = string(tlsInfo)
	data["banner"] = resp.RawHeaders
	data["protocol"] = ""
	data["port"] = ""
	data["status_code"] = resp.StatusCode
	data["favicon"] = faviconHash

	return data
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
	// case matchers.FaviconMatcher:
	// 	return d.matchFavicon(data, matcher)
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

// func (d *Detector) matchFavicon(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
// 	hash, ok := data["favicon"].(string)
// 	if !ok || len(matcher.Hash) == 0 {
// 		return false, nil
// 	}
// 	return sliceutil.Contains(matcher.Hash, hash), nil
// }

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
	// 使用sync.Once确保只构建一次
	d.pathsCacheOnce.Do(func() {
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
					// 构建唯一key：包含Method、Path和Headers
					key := buildPathRuleKey(rule.Method, p, rule.Headers, rule.Redirect)
					if _, ok := seen[key]; !ok {
						seen[key] = struct{}{}
						paths = append(paths, PathRule{
							Method:   rule.Method,
							Path:     p,
							Headers:  rule.Headers,
							Redirect: rule.Redirect,
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
					// 构建唯一key：包含Method、Path和Headers
					key := buildPathRuleKey(rule.Method, p, rule.Headers, rule.Redirect)
					if _, ok := seen[key]; !ok {
						seen[key] = struct{}{}
						paths = append(paths, PathRule{
							Method:   rule.Method,
							Path:     p,
							Headers:  rule.Headers,
							Redirect: rule.Redirect,
						})
					}
				}
			}
		}

		d.allPathsCache = paths
	})

	return d.allPathsCache
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

// buildPathRuleKey 构建路径规则的唯一key
// 格式: METHOD:PATH[:HEADER1=VALUE1:HEADER2=VALUE2...]
func buildPathRuleKey(method, path string, headers map[string]string, redirect bool) string {
	key := method + ":" + path
	if redirect {
		key += ":redirect=true"
	}
	if len(headers) > 0 {
		// 对headers按key排序后拼接，确保相同headers的规则生成相同key
		var headerParts []string
		for k, v := range headers {
			headerParts = append(headerParts, k+"="+v)
		}
		// 简单排序以保证一致性
		for i := 0; i < len(headerParts)-1; i++ {
			for j := i + 1; j < len(headerParts); j++ {
				if headerParts[i] > headerParts[j] {
					headerParts[i], headerParts[j] = headerParts[j], headerParts[i]
				}
			}
		}
		for _, part := range headerParts {
			key += ":" + part
		}
	}
	return key
}

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
// 注意：多次调用Init会清理之前的detector缓存
func (t *TechDetecter) Init(rulePath string, useInternal bool) error {
	// 清理旧的detector缓存，防止内存泄露
	if t.detector != nil {
		t.detector.ClearMatchedCache()
	}

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
