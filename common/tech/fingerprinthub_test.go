package tech

import (
	"sync"
	"testing"

	"github.com/Mzack9999/gcache"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

func newMatchedCacheForTest() gcache.Cache[string, *sync.Map] {
	return gcache.New[string, *sync.Map](32).LRU().Build()
}

func TestParseSelfHostedDSLRule(t *testing.T) {
	store := &RuleStore{
		dslRules:            make(map[string][]*CompiledRule),
		nucleiRules:         make(map[string][]*CompiledNucleiRule),
		fingerprintHubRules: make(map[string][]*CompiledFingerprintHubRule),
	}
	parser := newRuleParser(store)

	content := []byte(`
info:
  category: development framework
  company: Apache Software Foundation.
  cpe: ''
  product: apache-shiro
  server: nginx
  tags: []
rules:
- dsl: icontains(banner,"rememberme=deleteme")
  method: GET
  headers:
    Cookie: rememberMe=EC3EE66D1D64B846FB57C8CD4858
  redirect: false
`)

	require.NoError(t, parser.parseDSLRule(content))
	parser.compileAllDSLRules()

	require.Len(t, store.dslRules["apache-shiro"], 1)
	rule := store.dslRules["apache-shiro"][0]
	require.Equal(t, "GET", rule.Method)
	require.Equal(t, "rememberMe=EC3EE66D1D64B846FB57C8CD4858", rule.Headers["Cookie"])
	require.False(t, rule.Redirect)
}

func TestParseFingerprintHubFaviconRule(t *testing.T) {
	store := &RuleStore{
		dslRules:            make(map[string][]*CompiledRule),
		nucleiRules:         make(map[string][]*CompiledNucleiRule),
		fingerprintHubRules: make(map[string][]*CompiledFingerprintHubRule),
	}
	parser := newRuleParser(store)

	content := []byte(`
id: yonyou
info:
  name: yonyou
  author: cn-kali-team
  tags: detect,tech,yonyou
  severity: info
  metadata:
    product: yonyou-product
http:
- method: GET
  path:
  - '{{BaseURL}}/'
  matchers:
  - type: favicon
    hash:
    - '1085941792'
`)

	require.NoError(t, parser.parseFingerprintHubRule(content))
	require.Len(t, store.fingerprintHubRules["yonyou-product"], 1)

	rule := store.fingerprintHubRules["yonyou-product"][0]
	require.Equal(t, "GET", rule.Method)
	require.Equal(t, []string{"/"}, rule.Paths)
	require.Equal(t, []string{"1085941792"}, rule.FaviconHashes)
}

func TestFingerprintHubFaviconUsesMMH3WithoutChangingMD5Context(t *testing.T) {
	d := &Detector{
		store: &RuleStore{
			dslRules:            make(map[string][]*CompiledRule),
			nucleiRules:         make(map[string][]*CompiledNucleiRule),
			fingerprintHubRules: make(map[string][]*CompiledFingerprintHubRule),
		},
		matchedCache: newMatchedCacheForTest(),
	}
	d.store.fingerprintHubRules["zimbra"] = []*CompiledFingerprintHubRule{{
		Method:        "GET",
		Paths:         []string{"/"},
		FaviconHashes: []string{"475145467"},
	}}

	resp := &httpx.Response{Headers: map[string][]string{}, Data: []byte("body"), StatusCode: 200}
	results, err := d.DetectWithNuclei("http://example.com", "/", "GET", "d41d8cd98f00b204e9800998ecf8427e", resp, "475145467")

	require.NoError(t, err)
	require.Equal(t, []string{"zimbra"}, results)

	data := responseToDSLMap(resp, "", "", "", "", "body", "", "d41d8cd98f00b204e9800998ecf8427e", 0, nil)
	require.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", data["favicon"])
	require.Nil(t, data["favicon_mmh3"])
}

func TestFingerprintHubPathIncludedInActivePaths(t *testing.T) {
	d := &Detector{
		store: &RuleStore{
			dslRules:            make(map[string][]*CompiledRule),
			nucleiRules:         make(map[string][]*CompiledNucleiRule),
			fingerprintHubRules: make(map[string][]*CompiledFingerprintHubRule),
		},
		matchedCache: newMatchedCacheForTest(),
	}
	d.store.fingerprintHubRules["custom"] = []*CompiledFingerprintHubRule{{
		Method:        "POST",
		Paths:         []string{"/login"},
		Headers:       map[string]string{"X-Test": "yes"},
		Redirect:      true,
		FaviconHashes: []string{"123"},
	}}

	paths := d.GetAllPaths()

	require.Len(t, paths, 1)
	require.Equal(t, "POST", paths[0].Method)
	require.Equal(t, "/login", paths[0].Path)
	require.Equal(t, "yes", paths[0].Headers["X-Test"])
	require.True(t, paths[0].Redirect)
}
