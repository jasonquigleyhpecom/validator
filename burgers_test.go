package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	valerrs "github.com/pb33f/libopenapi-validator/errors"
	"github.com/pb33f/libopenapi-validator/paths"
	schema "github.com/pb33f/libopenapi-validator/schema_validation"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	"github.com/stretchr/testify/assert"
)

type requestTest struct {
	name        string
	method      string
	path        string
	contentType string
	payload     string
	fields      map[string]string
	result      int
	assertions  func(t *testing.T, resp *httptest.ResponseRecorder)
}

var burgerTests = []requestTest{ //nolint: gochecknoglobals
	{
		name:        "success",
		method:      http.MethodPost,
		path:        path,
		contentType: contentType,
		payload:     payloadGood,
		result:      http.StatusCreated,
	},
	{
		name:        "error-not-allowed",
		method:      http.MethodPost,
		path:        path,
		contentType: contentType,
		payload:     payloadBad,
		result:      http.StatusBadRequest,
	},
}

func TestBurgersDirectSharedModel(t *testing.T) {
	t.Parallel()
	model := initialiseDocumentModel([]byte(specFile))
	for i := 0; i < 100; i++ {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			validate(model)
		})
	}
}

func TestBurgersDirectRebuildModel(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			main()
		})
	}
}

func TestBurgersGinSharedModel(t *testing.T) {
	t.Parallel()

	addRoutes := func(router *gin.Engine) {
		router.POST(path, func(c *gin.Context) {
			c.JSON(http.StatusCreated, payloadGood)
		})
	}

	router := gin.Default()
	router.Use(OpenAPIRequestValidatorSharedModel([]byte(specFile)))
	addRoutes(router)

	for _, test := range burgerTests {
		test := test
		name := fmt.Sprintf("%s-%s", strings.ToLower(test.method), test.name)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runTest(t, router, test)
		})
	}
}

func TestBurgersGinRebuildModel(t *testing.T) {
	t.Parallel()

	addRoutes := func(router *gin.Engine) {
		router.POST(path, func(c *gin.Context) {
			c.JSON(http.StatusCreated, payloadGood)
		})
	}

	router := gin.Default()
	router.Use(OpenAPIRequestValidatorRebuildModel([]byte(specFile)))
	addRoutes(router)

	for _, test := range burgerTests {
		test := test
		name := fmt.Sprintf("%s-%s", strings.ToLower(test.method), test.name)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runTest(t, router, test)
		})
	}
}

func OpenAPIRequestValidatorSharedModel(specBytes []byte) gin.HandlerFunc {
	model := initialiseDocumentModel(specBytes)

	return func(c *gin.Context) {
		requestPath := c.Request.URL.String()

		// Try to find a path from the document model to validate against
		pathItem, verrors, _ := paths.FindPath(c.Request, &model.Model)
		if len(verrors) != 0 {
			reason := verrors[0].Reason

			if strings.Contains(reason, "path does not exist") {
				c.JSON(http.StatusNotFound, "NOT FOUND")
				c.Abort()

				return
			}

			c.JSON(http.StatusInternalServerError, "INTERNAL SERVER ERROR")
			c.Abort()

			return
		}

		// Only PATCH, POST and PUT should have bodies to validate
		switch c.Request.Method {
		case http.MethodPatch, http.MethodPost, http.MethodPut:
			break
		default:
			c.Next()

			return
		}

		// Make a copy of the body
		bodyBytes, ok := copyRequestBody(c)
		if !ok {
			makeErrBadRequestAndAbort(c, "no body")

			return
		}

		// Try to find a matching content type from the document model to validate against
		contentType := c.Request.Header.Get("Content-Type")

		var content *v3.MediaType

		var exists bool

		switch c.Request.Method {
		case http.MethodPatch:
			content, exists = pathItem.Patch.RequestBody.Content[contentType]
		case http.MethodPost:
			content, exists = pathItem.Post.RequestBody.Content[contentType]
		case http.MethodPut:
			content, exists = pathItem.Put.RequestBody.Content[contentType]
		}

		if !exists {
			makeErrBadRequestAndAbort(c, "not allowed",
				fmt.Sprintf("%s of %s not allowed at %s", c.Request.Method, contentType, requestPath))

			return
		}

		// Validate against the schema for the request path
		sch := content.Schema
		validator := schema.NewSchemaValidator()

		valid, verrors := validator.ValidateSchemaBytes(sch.Schema(), bodyBytes)
		if !valid {
			reasons := assembleValidationErrorReasons(verrors)
			makeErrBadRequestAndAbort(c, "validation error", reasons...)

			return
		}

		c.Next()
	}
}

func OpenAPIRequestValidatorRebuildModel(specBytes []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		model := initialiseDocumentModel(specBytes)
		requestPath := c.Request.URL.String()

		// Try to find a path from the document model to validate against
		pathItem, verrors, _ := paths.FindPath(c.Request, &model.Model)
		if len(verrors) != 0 {
			reason := verrors[0].Reason

			if strings.Contains(reason, "path does not exist") {
				c.JSON(http.StatusNotFound, "NOT FOUND")
				c.Abort()

				return
			}

			c.JSON(http.StatusInternalServerError, "INTERNAL SERVER ERROR")
			c.Abort()

			return
		}

		// Only PATCH, POST and PUT should have bodies to validate
		switch c.Request.Method {
		case http.MethodPatch, http.MethodPost, http.MethodPut:
			break
		default:
			c.Next()

			return
		}

		// Make a copy of the body
		bodyBytes, ok := copyRequestBody(c)
		if !ok {
			makeErrBadRequestAndAbort(c, "no body")

			return
		}

		// Try to find a matching content type from the document model to validate against
		contentType := c.Request.Header.Get("Content-Type")

		var content *v3.MediaType

		var exists bool

		switch c.Request.Method {
		case http.MethodPatch:
			content, exists = pathItem.Patch.RequestBody.Content[contentType]
		case http.MethodPost:
			content, exists = pathItem.Post.RequestBody.Content[contentType]
		case http.MethodPut:
			content, exists = pathItem.Put.RequestBody.Content[contentType]
		}

		if !exists {
			makeErrBadRequestAndAbort(c, "not allowed",
				fmt.Sprintf("%s of %s not allowed at %s", c.Request.Method, contentType, requestPath))

			return
		}

		// Validate against the schema for the request path
		sch := content.Schema
		validator := schema.NewSchemaValidator()

		valid, verrors := validator.ValidateSchemaBytes(sch.Schema(), bodyBytes)
		if !valid {
			reasons := assembleValidationErrorReasons(verrors)
			makeErrBadRequestAndAbort(c, "validation error", reasons...)

			return
		}

		c.Next()
	}
}

func assembleValidationErrorReasons(verrors []*valerrs.ValidationError) []string {
	var reasons []string

	for _, verror := range verrors {
		for _, serr := range verror.SchemaValidationErrors {
			reason := strings.ReplaceAll(serr.Reason, "'", "")

			switch {
			case reason == "allOf failed":
				continue
			case strings.HasPrefix(reason, "missing properties"):
				reason = strings.ReplaceAll(reason, "missing properties", "missing property")
			default:
				reason += ": " + strings.TrimPrefix(serr.Location, "/")
			}

			reasons = append(reasons, reason)
		}
	}

	return reasons
}

func copyRequestBody(c *gin.Context) ([]byte, bool) {
	// Avoid a panic if the body is not set
	if c.Request.Body == nil {
		return nil, false
	}

	// Make a copy of the body
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, false
	}

	if len(bodyBytes) == 0 {
		return nil, false
	}

	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	return bodyBytes, true
}

func makeErrBadRequestAndAbort(c *gin.Context, subject string, reasons ...string) {
	c.JSON(http.StatusBadRequest, reasons)
	c.Abort()
}

func makeErrInternalErrorAndAbort(c *gin.Context, subject string) {
	c.JSON(http.StatusInternalServerError, "Internal server error")
	c.Abort()
}

func makeErrNotFoundAndAbort(c *gin.Context, subject string) {
	c.JSON(http.StatusNotFound, "Not found")
	c.Abort()
}

func makeRequest(t *testing.T, method, path, contentType string, payload ...string) *http.Request {
	t.Helper()

	var payloadReader bytes.Reader

	if len(payload) != 0 {
		payloadReader = *bytes.NewReader([]byte(payload[0]))
	}

	req, _ := http.NewRequestWithContext(context.Background(), method, path, &payloadReader)

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return req
}

func readBadRequestError(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return string(body)
}

func runTest(t *testing.T, router *gin.Engine, test requestTest) {
	t.Helper()

	resp := httptest.NewRecorder()

	var req *http.Request

	if test.payload == "" {
		req = makeRequest(t, test.method, test.path, test.contentType)
	} else {
		if test.fields != nil {
			test.payload = setFields(test.payload, test.fields)
		}
		req = makeRequest(t, test.method, test.path, test.contentType, test.payload)
	}

	router.ServeHTTP(resp, req)

	assert.Equal(t, test.result, resp.Code)
	fmt.Println(readBadRequestError(t, resp))
	if test.assertions != nil {
		test.assertions(t, resp)
	}
}

func setFields(payload string, fields map[string]string) string {
	for k, v := range fields {
		payload = strings.ReplaceAll(payload, "--"+k+"--", v)
	}

	return payload
}
