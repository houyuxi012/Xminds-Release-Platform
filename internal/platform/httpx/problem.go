package httpx

import (
	"encoding/json"
	"net/http"
)

const ProblemMediaType = "application/problem+json"

type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Instance  string `json:"instance,omitempty"`
	Code      string `json:"code"`
	RequestID string `json:"request_id,omitempty"`

	cause error
}

func NewProblem(status int, code string, title string, cause error) Problem {
	return Problem{
		Type:   "about:blank",
		Title:  title,
		Status: status,
		Code:   code,
		cause:  cause,
	}
}

func (problem Problem) WithRequestID(requestID string) Problem {
	problem.RequestID = requestID
	return problem
}

func (problem Problem) WithDetail(detail string) Problem {
	problem.Detail = detail
	return problem
}

func (problem Problem) WithInstance(instance string) Problem {
	problem.Instance = instance
	return problem
}

func (problem Problem) Cause() error {
	return problem.cause
}

func WriteProblem(writer http.ResponseWriter, problem Problem) {
	payload, err := json.Marshal(problem)
	if err != nil {
		problem = NewProblem(
			http.StatusInternalServerError,
			"PROBLEM_SERIALIZATION_FAILED",
			"Internal server error",
			err,
		)
		payload = []byte(`{"type":"about:blank","title":"Internal server error","status":500,"code":"PROBLEM_SERIALIZATION_FAILED"}`)
	}

	writer.Header().Set("Content-Type", ProblemMediaType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(problem.Status)
	_, _ = writer.Write(append(payload, '\n'))
}
