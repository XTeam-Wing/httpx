package httpx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	t.Run("content-length in header", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://scanme.sh", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	})

	t.Run("content-length with binary body", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://www.w3schools.com/images/favicon.ico", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Greater(t, len(resp.Raw), 800)
	})
}

func TestHTTP11DisablesRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions
	options.Protocol = HTTP11

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.Same(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}

func TestDefaultProtocolKeepsRetryableHTTP2FallbackClient(t *testing.T) {
	options := DefaultOptions

	ht, err := New(&options)
	require.NoError(t, err)
	require.NotNil(t, ht.client)
	require.NotSame(t, ht.client.HTTPClient, ht.client.HTTPClient2)
}
