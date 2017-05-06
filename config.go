package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"path/filepath"
)

var backends = map[string]struct{}{
	"hugo": struct{}{},
	"hexo": struct{}{},
	"pdf":  struct{}{},
	"raw":  struct{}{},
}

type atConfigTys struct {
	SiteURL string
}

var atConfig atConfigTys

func init() {

	cfgStr, err := ioutil.ReadFile(filepath.Join("config.json"))
	if err != nil {
		// Handle error
		log.Println(err)
		panic(err)
	}

	if err = json.Unmarshal(cfgStr, &atConfig); err != nil {
		log.Println(err)
		panic(err)
	}
}
