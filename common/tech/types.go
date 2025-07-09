package tech

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
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
	CEL    string `yaml:"cel"`
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
