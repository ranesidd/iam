package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type HTTPContentType string

const (
	HTTPContentTypeAppJSON HTTPContentType = "application/json"
)

func IsEmpty(str string) bool {
	return len(strings.TrimSpace(str)) == 0
}

func HttpPost(ctx context.Context, url string, headers map[string][]string, body io.Reader, responseObjPtr interface{}) error {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return err
	}

	for key, values := range headers {
		for _, value := range values {
			httpRequest.Header.Add(key, value)
		}
	}

	httpResponse, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		return err
	}

	defer httpResponse.Body.Close()
	responseData, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return err
	}

	if httpResponse.StatusCode > 299 {
		errorMessage := fmt.Sprintf(string(responseData)+". StatusCode = %d", httpResponse.StatusCode)
		return errors.New(errorMessage)
	}

	if IsEmpty(string(responseData)) {
		return nil
	}

	return json.Unmarshal(responseData, responseObjPtr)
}

func AnyToPtr[T any](value T) *T {
	return &value
}
