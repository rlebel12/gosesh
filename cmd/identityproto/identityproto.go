package main

import (
	_ "embed"
	"flag"
	"log"
	"os"
	"text/template"
)

const (
	tmplFile  = "internal/identityproto.tmpl"
	protoFile = "identity.proto"
)

//go:embed internal/identityproto.tmpl
var tmplRaw []byte

type tmplData struct {
	Package string
}

func main() {
	var goPkg string
	flag.StringVar(&goPkg, "package", "", "package name")
	flag.StringVar(&goPkg, "p", "", "package name (shorthand)")
	flag.Parse()

	if goPkg == "" {
		log.Fatal("package name is required")
	}

	data := tmplData{
		Package: goPkg,
	}

	tmpl, err := template.New(tmplFile).Parse(string(tmplRaw))
	if err != nil {
		log.Fatal("failed to parse template: ", err)
	}

	path := "./" + protoFile
	file, err := os.Create(path)
	if err != nil {
		log.Fatal("failed to create file: ", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, data)
	if err != nil {
		log.Fatal("failed to execute template: ", err)
	}
}
