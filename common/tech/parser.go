package tech

import (
	"errors"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
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
	Method string
	Paths  []string
	DSL    string
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

	for _, rule := range m.Rules {
		if rule.DSL == "" {
			continue
		}
		paths := rule.Path
		if len(paths) == 0 {
			paths = []string{"/"}
		}
		p.rawDSL[product] = append(p.rawDSL[product], rawDSLRule{
			Method: rule.Method,
			Paths:  paths,
			DSL:    rule.DSL,
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
			Expression: compiled,
		})
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
				Expression: expr,
			})
		}
	}
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
