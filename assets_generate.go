// +build ignore

package main

import (
	"log"

	"github.com/shurcooL/vfsgen"
)

func main() {
	err := vfsgen.Generate(Assets, vfsgen.Options{BuildTags: "embed", VariableName: "Assets"})
	if err != nil {
		log.Fatalln(err)
	}
}
