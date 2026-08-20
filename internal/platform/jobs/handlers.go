package jobs

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

var errorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)

type Handler interface {
	Handle(ctx context.Context, job Job) error
}

type HandlerFunc func(context.Context, Job) error

func (function HandlerFunc) Handle(ctx context.Context, job Job) error {
	return function(ctx, job)
}

type HandlerRegistry struct {
	handlers map[string]Handler
}

type DeadLetterRegistry struct {
	handlers map[string]DeadLetterHandler
}

func NewDeadLetterRegistry(handlers map[string]DeadLetterHandler) *DeadLetterRegistry {
	registry := &DeadLetterRegistry{handlers: make(map[string]DeadLetterHandler, len(handlers))}
	for kind, handler := range handlers {
		kind = strings.TrimSpace(kind)
		if kind != "" && handler != nil {
			registry.handlers[kind] = handler
		}
	}
	return registry
}

func (registry *DeadLetterRegistry) HandleDeadLetter(ctx context.Context, job Job, code string) error {
	if registry == nil {
		return errors.New("dead-letter registry is not configured")
	}
	handler, exists := registry.handlers[strings.TrimSpace(job.Kind)]
	if !exists {
		return errors.New("dead-letter handler is not registered")
	}
	return handler.HandleDeadLetter(ctx, job, code)
}

func (registry *DeadLetterRegistry) ResolveTransactionalDeadLetter(kind string) (TransactionalDeadLetterHandler, bool) {
	if registry == nil {
		return nil, false
	}
	handler, exists := registry.handlers[strings.TrimSpace(kind)]
	if !exists {
		return nil, false
	}
	transactional, ok := handler.(TransactionalDeadLetterHandler)
	return transactional, ok
}

func NewHandlerRegistry(handlers map[string]Handler) *HandlerRegistry {
	registry := &HandlerRegistry{handlers: make(map[string]Handler, len(handlers))}
	for kind, handler := range handlers {
		kind = strings.TrimSpace(kind)
		if kind != "" && handler != nil {
			registry.handlers[kind] = handler
		}
	}
	return registry
}

func (registry *HandlerRegistry) Resolve(kind string) (Handler, bool) {
	if registry == nil {
		return nil, false
	}
	handler, exists := registry.handlers[strings.TrimSpace(kind)]
	return handler, exists
}

type codedError struct {
	code string
	err  error
}

func NewCodedError(code string, err error) error {
	code = strings.TrimSpace(code)
	if err == nil {
		err = errors.New("job handler failed")
	}
	if !errorCodePattern.MatchString(code) || len(code) > 128 {
		code = "job_handler_failed"
	}
	return &codedError{code: code, err: err}
}

func (err *codedError) Error() string { return err.err.Error() }
func (err *codedError) Unwrap() error { return err.err }
func (err *codedError) Code() string  { return err.code }

func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	type codeCarrier interface{ Code() string }
	var carrier codeCarrier
	if errors.As(err, &carrier) && errorCodePattern.MatchString(carrier.Code()) && len(carrier.Code()) <= 128 {
		return carrier.Code()
	}
	return "job_handler_failed"
}
