package tech

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
)

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

type Rule struct {
	Method string   `yaml:"method"`
	Path   []string `yaml:"path"`
	DSL    string   `yaml:"dsl"`
}

type Matchers struct {
	Info  Info   `yaml:"info"`
	Rules []Rule `yaml:"rules"`
}

// matchers
type FingerPrint struct {
	Name       string
	Conditions []string
}

// Nuclei Template Info
type NucleiInfo struct {
	Name           string                 `json:"name,omitempty" yaml:"name,omitempty" jsonschema:"title=name of the template,description=Name is a short summary of what the template does,type=string,required,example=Nagios Default Credentials Check"`
	Authors        string                 `json:"author,omitempty" yaml:"author,omitempty" jsonschema:"title=author of the template,description=Author is the author of the template,required,example=username"`
	Tags           string                 `json:"tags,omitempty" yaml:"tags,omitempty" jsonschema:"title=tags of the template,description=Any tags for the template"`
	Description    string                 `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"title=description of the template,description=In-depth explanation on what the template does,type=string,example=Bower is a package manager which stores package information in the bower.json file"`
	SeverityHolder string                 `json:"severity,omitempty" yaml:"severity,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty" jsonschema:"title=additional metadata for the template,description=Additional metadata fields for the template,type=object"`
}

type Template struct {
	ID               string         `yaml:"id" json:"id" jsonschema:"title=id of the template,description=The Unique ID for the template,required,example=cve-2021-19520,pattern=^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"`
	Info             NucleiInfo     `yaml:"info" json:"info" jsonschema:"title=info for the template,description=Info contains metadata for the template,required,type=object"`
	RequestsWithHTTP []*HTTPRequest `yaml:"http,omitempty" json:"http,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template"`
}

type HTTPRequest struct {
	Method              string            `json:"method,omitempty" yaml:"method,omitempty" jsonschema:"title=http method,description=HTTP Method to use for the request,example=GET"`
	Headers             map[string]string `yaml:"headers,omitempty" json:"headers,omitempty" jsonschema:"title=headers to send with the http request,description=Headers contains HTTP Headers to send with the request"`
	Path                []string          `json:"path,omitempty" yaml:"path,omitempty" jsonschema:"title=http path,description=HTTP Path to use for the request,example=/api/v1/resource"`
	operators.Operators `yaml:",inline" json:",inline"`
}

// Compile compiles the protocol request for further execution.
func (request *HTTPRequest) Compile() *operators.Operators {
	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		if compileErr := compiled.Compile(); compileErr != nil {
			return nil
		}
		return compiled
	}
	return nil
}
