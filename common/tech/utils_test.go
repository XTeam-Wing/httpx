package tech

import (
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

func TestResponseToDSLMapKeepsFaviconMD5(t *testing.T) {
	const faviconMD5 = "d41d8cd98f00b204e9800998ecf8427e"

	data := responseToDSLMap(&httpx.Response{
		Headers: map[string][]string{},
		Data:    []byte("body"),
	}, "", "", "", "", "body", "", faviconMD5, 0, nil)

	require.Equal(t, faviconMD5, data["favicon"])
}

func TestBuildPathRuleKeyIncludesRedirect(t *testing.T) {
	headers := map[string]string{"X-Test": "yes"}

	withoutRedirect := buildPathRuleKey("GET", "/admin", headers, false)
	withRedirect := buildPathRuleKey("GET", "/admin", headers, true)

	require.NotEqual(t, withoutRedirect, withRedirect)
}
