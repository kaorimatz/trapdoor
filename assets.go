// +build !embed

//go:generate go run assets.go assets_generate.go

package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/shurcooL/httpfs/filter"
)

var Assets = func() http.FileSystem {
	return filter.Keep(http.Dir("."), func(path string, fi os.FileInfo) bool {
		return path == "/" ||
			path == "/index.html.tmpl" ||
			path == "/js" ||
			strings.HasPrefix(path, "/js/")
	})
}()
