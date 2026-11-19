package server

import (
	"net/http"
	"net/url"

	"fileshare/internal/files"
)

func urlQuery(r *http.Request) (url.Values, error) {
	v, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	if values, ok := v["path"]; ok && len(values) != 1 {
		return nil, files.ErrDenied
	}
	return v, nil
}
