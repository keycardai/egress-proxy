// Negative fixture for the vulnerability gate: reaches a vulnerable symbol.
package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	tags, _, err := language.ParseAcceptLanguage(os.Getenv("ACCEPT_LANGUAGE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(tags)
}
