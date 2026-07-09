package tech

import (
	"errors"
	"fmt"
	"strings"

	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"gopkg.in/yaml.v3"
)

// ruleParser 规则解析器
type ruleParser struct {
	store      *RuleStore
	rawDSL     map[string][]rawDSLRule // 待编译的DSL规则
	helperFunc map[string]govaluate.ExpressionFunction
}

type rawDSLRule struct {
	Method   string
	Paths    []string
	Headers  map[string]string
	Redirect bool
	DSL      string
}

func newRuleParser(store *RuleStore) *ruleParser {
	p := &ruleParser{
		store:      store,
		rawDSL:     make(map[string][]rawDSLRule),
		helperFunc: make(map[string]govaluate.ExpressionFunction),
	}
	p.initHelperFunctions()
	return p
}

func (p *ruleParser) initHelperFunctions() {
	// 复制DSL默认函数
	for name, fn := range dsl.DefaultHelperFunctions {
		p.helperFunc[name] = fn
	}
	// 添加自定义函数
	p.helperFunc["icontains"] = func(args ...interface{}) (interface{}, error) {
		return strings.Contains(strings.ToLower(toString(args[0])), strings.ToLower(toString(args[1]))), nil
	}
}

// parseDSLRule 解析DSL规则
func (p *ruleParser) parseDSLRule(content []byte) error {
	var m Matchers
	if err := yaml.Unmarshal(content, &m); err != nil {
		return err
	}

	product := m.Info.Product
	if product == "" {
		return errors.New("product name is empty")
	}

	// 如果产品已存在规则，跳过（避免重复加载）
	if _, exists := p.rawDSL[product]; exists {
		return nil
	}

	for _, rule := range m.Rules {
		if rule.DSL == "" {
			continue
		}
		paths := rule.Path
		if len(paths) == 0 {
			paths = []string{"/"}
		}
		p.rawDSL[product] = append(p.rawDSL[product], rawDSLRule{
			Method:   rule.Method,
			Paths:    paths,
			Headers:  rule.Headers,
			Redirect: rule.Redirect,
			DSL:      rule.DSL,
		})
	}
	return nil
}

// parseNucleiRule 解析Nuclei规则
func (p *ruleParser) parseNucleiRule(content []byte) error {
	var t Template
	if err := yaml.Unmarshal(content, &t); err != nil {
		return err
	}

	product := t.Info.Name
	if product == "" {
		return errors.New("template name is empty")
	}

	p.store.mu.Lock()
	defer p.store.mu.Unlock()

	// 如果产品已存在规则，跳过（避免重复加载）
	if _, exists := p.store.nucleiRules[product]; exists {
		return nil
	}

	for _, req := range t.RequestsWithHTTP {
		compiled := req.Compile()
		if compiled == nil {
			continue
		}

		method := req.Method
		if method == "" {
			method = "GET"
		}

		paths := make([]string, 0, len(req.Path))
		for _, pt := range req.Path {
			paths = append(paths, strings.ReplaceAll(pt, "{{BaseURL}}", ""))
		}

		p.store.nucleiRules[product] = append(p.store.nucleiRules[product], &CompiledNucleiRule{
			Method:     method,
			Paths:      paths,
			Headers:    req.Headers,
			Redirect:   false, // Nuclei规则默认不跟随重定向
			Expression: compiled,
		})
	}
	return nil
}

// parseFingerprintHubRule 解析FingerprintHub兼容规则
func (p *ruleParser) parseFingerprintHubRule(content []byte) error {
	var t fingerprintHubTemplate
	if err := yaml.Unmarshal(content, &t); err != nil {
		return err
	}

	if len(t.RequestsWithHTTP) == 0 {
		return errors.New("fingerprinthub http requests is empty")
	}

	product := t.productName()
	if product == "" {
		return errors.New("fingerprinthub product name is empty")
	}

	p.store.mu.Lock()
	defer p.store.mu.Unlock()

	if _, exists := p.store.fingerprintHubRules[product]; exists {
		return nil
	}

	for _, req := range t.RequestsWithHTTP {
		rule, err := req.compile()
		if err != nil {
			gologger.Warning().Msgf("compile FingerprintHub rule for %s: %s", product, err)
			continue
		}
		if rule == nil {
			continue
		}
		p.store.fingerprintHubRules[product] = append(p.store.fingerprintHubRules[product], rule)
	}

	if len(p.store.fingerprintHubRules[product]) == 0 {
		delete(p.store.fingerprintHubRules, product)
		return errors.New("fingerprinthub rule has no supported matchers")
	}

	return nil
}

// compileAllDSLRules 编译所有DSL规则
func (p *ruleParser) compileAllDSLRules() {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()

	for product, rules := range p.rawDSL {
		for _, rule := range rules {
			expr, err := govaluate.NewEvaluableExpressionWithFunctions(rule.DSL, p.helperFunc)
			if err != nil {
				gologger.Error().Msgf("compile DSL for %s: %s", product, err)
				continue
			}

			p.store.dslRules[product] = append(p.store.dslRules[product], &CompiledRule{
				Method:     rule.Method,
				Paths:      rule.Paths,
				Headers:    rule.Headers,
				Redirect:   rule.Redirect,
				Expression: expr,
			})
		}
	}

	// 清理原始DSL数据以释放内存
	p.rawDSL = nil
	p.helperFunc = nil
}

// ============================================================================
// 规则类型定义
// ============================================================================

// Info 规则信息
type Info struct {
	Company     string   `yaml:"company"`
	Author      string   `yaml:"author"`
	Product     string   `yaml:"product"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
	Category    string   `yaml:"category"`
	Tags        []string `yaml:"tags"`
	CPE         string   `yaml:"cpe"`
	FoFaQuery   string   `yaml:"fofa_query"`
}

// Rule DSL规则
type Rule struct {
	Method   string            `yaml:"method"`
	Path     []string          `yaml:"path"`
	DSL      string            `yaml:"dsl"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Redirect bool              `yaml:"redirect"`
}

// Matchers DSL规则匹配器
type Matchers struct {
	Info  Info   `yaml:"info"`
	Rules []Rule `yaml:"rules"`
}

// FingerPrint 指纹信息
type FingerPrint struct {
	Name       string
	Conditions []string
}

// ============================================================================
// Nuclei模板类型定义
// ============================================================================

// NucleiInfo Nuclei模板信息
type NucleiInfo struct {
	Name           string                 `json:"name,omitempty" yaml:"name,omitempty"`
	Authors        string                 `json:"author,omitempty" yaml:"author,omitempty"`
	Tags           string                 `json:"tags,omitempty" yaml:"tags,omitempty"`
	Description    string                 `json:"description,omitempty" yaml:"description,omitempty"`
	SeverityHolder string                 `json:"severity,omitempty" yaml:"severity,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Template Nuclei模板
type Template struct {
	ID               string         `yaml:"id" json:"id"`
	Info             NucleiInfo     `yaml:"info" json:"info"`
	RequestsWithHTTP []*HTTPRequest `yaml:"http,omitempty" json:"http,omitempty"`
}

// HTTPRequest Nuclei HTTP请求
type HTTPRequest struct {
	Method              string            `json:"method,omitempty" yaml:"method,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Path                []string          `json:"path,omitempty" yaml:"path,omitempty"`
	operators.Operators `yaml:",inline" json:",inline"`
}

// Compile 编译HTTP请求的操作符
func (request *HTTPRequest) Compile() *operators.Operators {
	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		if compileErr := compiled.Compile(); compileErr != nil {
			gologger.Warning().Msgf("could not compile operators: %s", compileErr)
			return nil
		}
		return compiled
	}
	return nil
}

type stringSliceCompat []string

func (s *stringSliceCompat) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Value == "" {
			*s = nil
			return nil
		}
		parts := strings.Split(value.Value, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		*s = out
		return nil
	case yaml.SequenceNode:
		out := make([]string, 0, len(value.Content))
		for _, item := range value.Content {
			if item.Value != "" {
				out = append(out, item.Value)
			}
		}
		*s = out
		return nil
	default:
		return fmt.Errorf("unsupported string slice yaml node kind %d", value.Kind)
	}
}

// fingerprintHubTemplate 是0x727/FingerprintHub的轻量兼容结构。
type fingerprintHubTemplate struct {
	ID               string                       `yaml:"id" json:"id"`
	Info             fingerprintHubInfo           `yaml:"info" json:"info"`
	RequestsWithHTTP []*fingerprintHubHTTPRequest `yaml:"http,omitempty" json:"http,omitempty"`
}

type fingerprintHubInfo struct {
	Name     string                 `yaml:"name,omitempty" json:"name,omitempty"`
	Tags     stringSliceCompat      `yaml:"tags,omitempty" json:"tags,omitempty"`
	Metadata map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

type fingerprintHubHTTPRequest struct {
	Method            string                  `yaml:"method,omitempty" json:"method,omitempty"`
	Headers           map[string]string       `yaml:"headers,omitempty" json:"headers,omitempty"`
	Path              stringSliceCompat       `yaml:"path,omitempty" json:"path,omitempty"`
	Redirect          bool                    `yaml:"redirect,omitempty" json:"redirect,omitempty"`
	Redirects         bool                    `yaml:"redirects,omitempty" json:"redirects,omitempty"`
	MatchersCondition string                  `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty"`
	Matchers          []fingerprintHubMatcher `yaml:"matchers,omitempty" json:"matchers,omitempty"`
}

type fingerprintHubMatcher struct {
	Type            string            `yaml:"type,omitempty" json:"type,omitempty"`
	Condition       string            `yaml:"condition,omitempty" json:"condition,omitempty"`
	Part            string            `yaml:"part,omitempty" json:"part,omitempty"`
	Negative        bool              `yaml:"negative,omitempty" json:"negative,omitempty"`
	Name            string            `yaml:"name,omitempty" json:"name,omitempty"`
	Status          []int             `yaml:"status,omitempty" json:"status,omitempty"`
	Size            []int             `yaml:"size,omitempty" json:"size,omitempty"`
	Words           stringSliceCompat `yaml:"words,omitempty" json:"words,omitempty"`
	Regex           stringSliceCompat `yaml:"regex,omitempty" json:"regex,omitempty"`
	Binary          stringSliceCompat `yaml:"binary,omitempty" json:"binary,omitempty"`
	DSL             stringSliceCompat `yaml:"dsl,omitempty" json:"dsl,omitempty"`
	XPath           stringSliceCompat `yaml:"xpath,omitempty" json:"xpath,omitempty"`
	Hash            stringSliceCompat `yaml:"hash,omitempty" json:"hash,omitempty"`
	Encoding        string            `yaml:"encoding,omitempty" json:"encoding,omitempty"`
	CaseInsensitive bool              `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty"`
	MatchAll        bool              `yaml:"match-all,omitempty" json:"match-all,omitempty"`
	Internal        bool              `yaml:"internal,omitempty" json:"internal,omitempty"`
}

func (t *fingerprintHubTemplate) productName() string {
	if t.Info.Metadata != nil {
		if product, ok := t.Info.Metadata["product"].(string); ok && strings.TrimSpace(product) != "" {
			return strings.TrimSpace(product)
		}
	}
	if strings.TrimSpace(t.Info.Name) != "" {
		return strings.TrimSpace(t.Info.Name)
	}
	return strings.TrimSpace(t.ID)
}

func (request *fingerprintHubHTTPRequest) compile() (*CompiledFingerprintHubRule, error) {
	if len(request.Matchers) == 0 {
		return nil, nil
	}

	method := request.Method
	if method == "" {
		method = "GET"
	}

	paths := make([]string, 0, len(request.Path))
	for _, pt := range request.Path {
		pt = strings.ReplaceAll(pt, "{{BaseURL}}", "")
		if pt == "" {
			pt = "/"
		}
		paths = append(paths, pt)
	}
	if len(paths) == 0 {
		paths = []string{"/"}
	}

	rule := &CompiledFingerprintHubRule{
		Method:   method,
		Paths:    paths,
		Headers:  request.Headers,
		Redirect: request.Redirect || request.Redirects,
	}

	var ordinary []fingerprintHubMatcher
	for _, matcher := range request.Matchers {
		if strings.EqualFold(strings.TrimSpace(matcher.Type), "favicon") {
			rule.FaviconHashes = append(rule.FaviconHashes, matcher.Hash...)
			continue
		}
		ordinary = append(ordinary, matcher)
	}

	if len(ordinary) > 0 {
		expr, err := compileFingerprintHubOrdinaryMatchers(ordinary, request.MatchersCondition)
		if err != nil {
			return nil, err
		}
		rule.Expression = expr
	}

	if len(rule.FaviconHashes) == 0 && rule.Expression == nil {
		return nil, nil
	}

	return rule, nil
}

func compileFingerprintHubOrdinaryMatchers(matchers []fingerprintHubMatcher, condition string) (*operators.Operators, error) {
	operatorYAML, err := yaml.Marshal(map[string]interface{}{
		"matchers-condition": condition,
		"matchers":           matchers,
	})
	if err != nil {
		return nil, err
	}

	var ops operators.Operators
	if err := yaml.Unmarshal(operatorYAML, &ops); err != nil {
		return nil, err
	}
	if err := ops.Compile(); err != nil {
		return nil, err
	}
	return &ops, nil
}
