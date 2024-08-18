// utils/template.go

package utils

import (
	"github.com/flosch/pongo2/v6"
)

// LoadTemplate loads a Pongo2 template from the given path.
func LoadTemplate(templatePath string) (*pongo2.Template, error) {
	return pongo2.FromFile(templatePath)
}
