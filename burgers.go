package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/pb33f/libopenapi"
	schema "github.com/pb33f/libopenapi-validator/schema_validation"
	"github.com/pb33f/libopenapi/datamodel"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	"github.com/valyala/fastjson"
)

const (
	specFile = `
openapi: 3.1.0
info:
  title: Burgers
  license:
    name: License Agreement
    url: https://www.example.com/licensing.html
  version: latest
  description: |
    More burgers!
    A unified API for consuming burgers 
  contact:
    name: Ronald Macdonald
    email: burgers@example.com

servers:
  - url: https://api.example.com
    description: Development environment

externalDocs:
  description: Find out more about burgers
  url: https://www.example.com

security:
  - Bearer: []

paths:
  /burgers/create-burger:
    post:
      operationId: createBurger
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/burgerCreate'
            examples:
              pbjBurger:
                summary: A horrible, nutty, sticky mess.
                value:
                  name: Peanut And Jelly
                  patties: 3
                  vegetarian: true
        responses:
          '201':
            description: Burger created
            headers:
              Location:
                description: URL for the created burger
                schema:
                  type: string
                  format: uri
                example: burgers/0e7f516c-0829-4135-83d6-09ce844ddd9d

components:
  securitySchemes:
    Bearer:
      description: Uses a token for authorization
      type: http
      scheme: bearer
  schemas:
    burgerCreate:
      type: object
      required:
      - name
      - patties
      - vegetarian
      - deep
      properties:
        name:
          type: string
        patties:
          type: integer
        vegetarian:
          type: boolean
        deep:
          $ref: '#/components/schemas/somethingDeep'
        # garbage:
        #   type: boolean
      unevaluatedProperties: false
    somethingDeep:
      allOf:
      - type: object
        required:
        - deep
        - deeper
        properties:
          deep:
            type: integer
          deeper:
            $ref: '#/components/schemas/somethingDeeper'
    somethingDeeper:
      type: object
      required:
      - deeper
      - really_deep
      properties:
        deeper:
          type: integer
        really_deep:
          $ref: '#/components/schemas/reallyDeep'
    reallyDeep:
      type: object
      required:
      - really_deep
      - super_deep
      properties:
        really_deep:
          type: integer
        super_deep:
          $ref: '#/components/schemas/superDeep'
    superDeep:
      type: object
      required:
      - super_deep
      properties:
        super_deep:
          type: integer
`
	payloadGood = `
{
	"name": "Good burger",
	"patties": 2,
	"vegetarian": false,
	"deep": {
		"deep": 1,
		"deeper": {
			"deeper": 1,
			"really_deep": {
				"really_deep": 1,
				"super_deep": {
					"super_deep": 1
				}
			}
		}
	}
}
`
	payloadBad = `
{
	"name": "Garbage burger",
	"patties": 2,
	"garbage": true,
	"deep": {
		"deep": 1,
		"deeper": {
			"deeper": 1,
			"really_deep": {
				"really_deep": 1,
				"super_deep": {
					"super_deep": 1
				}
			}
		}
	}
}
`
	contentType = "application/json"
	path        = "/burgers/create-burger"
)

var ctRegex = regexp.MustCompile(`The content type .* it's an unknown type`)

func initialiseDocumentModel(specBytes []byte) *libopenapi.DocumentModel[v3.Document] {
	document, err := libopenapi.NewDocumentWithConfiguration(specBytes, &datamodel.DocumentConfiguration{})
	if err != nil {
		panic(err)
	}

	// Build a model
	docModel, errors := document.BuildV3Model()
	if len(errors) > 0 {
		var details string
		for i := range errors {
			details += fmt.Sprintf("error %d: %s\n", i+1, errors[i])
		}

		panic(fmt.Sprintf("cannot create v3 model from document: %d errors reported\n%s", len(errors), details))
	}

	return docModel
}

func validate(model *libopenapi.DocumentModel[v3.Document]) {
	request, err := http.NewRequest(http.MethodPost, "http://localhost"+path, bytes.NewReader([]byte(payloadGood)))
	if err != nil {
		panic(err)
	}
	request.Header.Set("Content-Type", contentType)

	bodyBytes, bodyErr := ioutil.ReadAll(request.Body)
	if bodyErr != nil {
		panic(bodyErr)
	}
	request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// Validate the body is proper JSON
	bodyErr = fastjson.ValidateBytes(bodyBytes)
	if bodyErr != nil {
		panic(bodyErr)
	}

	// Try to find a schema from the document model to validate against
	if item, ok := model.Model.Paths.PathItems[request.URL.Path]; ok {
		if content, ok := item.Post.RequestBody.Content[request.Header.Get("Content-Type")]; ok {
			sch := content.Schema
			v := schema.NewSchemaValidator()
			_, verrors := v.ValidateSchemaBytes(sch.Schema(), bodyBytes)
			if len(verrors) > 0 {
				for _, err := range verrors {
					for _, serr := range err.SchemaValidationErrors {
						msg := strings.ReplaceAll(serr.Reason, "'", "")
						msg += ": " + strings.TrimPrefix(serr.Location, "/")
						fmt.Printf("-------> %s\n", msg)
					}
				}
			}
		} else {
			fmt.Println("bad content type")
		}
	} else {
		fmt.Println("bad path error")
	}
}

func main() {
	model := initialiseDocumentModel([]byte(specFile))
	validate(model)
}
