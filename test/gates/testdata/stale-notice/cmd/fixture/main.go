// Command fixture stands in for a shipped binary. Its import is what NOTICE
// must attribute.
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	fmt.Println(language.English)
}
