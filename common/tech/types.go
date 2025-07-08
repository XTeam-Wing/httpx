package tech

type Info struct {
	Company  string `yaml:"company"`
	Product  string `yaml:"product"`
	Server   string `yaml:"server"`
	Category string `yaml:"category"`
	Tags     string `yaml:"tags"`
	CPE      string `yaml:"cpe"`
}

type Rule struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
	DSL    string `yaml:"dsl"`
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
