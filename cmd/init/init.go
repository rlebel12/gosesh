package main

import (
	"flag"
	"log"
	"os"
	"path"

	_ "embed"

	"github.com/rlebel12/identity/cmd/internal"
)

const (
	dirDefault = "./identity"
	dirUsage   = "directory to store identity data"
	fileName   = "generate.go"
)

//go:embed internal/gentemplate.go
var template []byte

func main() {
	var dir string
	internal.DirFlag(&dir)
	flag.Parse()

	err := ensureDir(dir)
	if err != nil {
		log.Fatal("failed to create directory: ", err)
	}

	err = ensureFile(dir)
	if err != nil {
		log.Fatal("failed to create file: ", err)
	}
}

func ensureDir(dir string) error {
	_, err := os.Stat(dir)
	if err == nil || os.IsExist(err) {
		return nil
	}
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return err
	}

	return nil
}

func ensureFile(dir string) error {
	path := path.Join(dir, fileName)
	return os.WriteFile(path, template, os.ModePerm)
}
