package poc

import (
	"bytes"
	"embed"
	"html/template"
)

//go:embed templates/poc.html
var files embed.FS

var tmpl = template.Must(template.ParseFS(files, "templates/poc.html"))

type Data struct {
	Description string
	Author      string
	TargetURL   string
	Domain      string
	Status      string
	StatusClass string
}

func Render(d Data) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
