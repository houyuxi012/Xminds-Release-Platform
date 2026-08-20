package iam

import (
	"context"
	"sync"
)

const (
	directorySecretIOWorkers   = 4
	directorySecretIOQueueSize = 32
)

type secretSnapshotRead func(name string) ([]byte, error)

type secretIOExecutor struct {
	requests chan secretIORequest
	stop     chan struct{}
	read     secretSnapshotRead
	once     sync.Once
	workers  sync.WaitGroup
}

type secretIORequest struct {
	ctx    context.Context
	name   string
	result chan secretIOResult
}

type secretIOResult struct {
	contents []byte
	err      error
}

func newSecretIOExecutor(workerCount, queueSize int, read secretSnapshotRead) *secretIOExecutor {
	if workerCount < 1 || queueSize < 1 || read == nil {
		return nil
	}
	executor := &secretIOExecutor{
		requests: make(chan secretIORequest, queueSize),
		stop:     make(chan struct{}),
		read:     read,
	}
	executor.workers.Add(workerCount)
	for range workerCount {
		go executor.run()
	}
	return executor
}

func (executor *secretIOExecutor) Resolve(ctx context.Context, name string) ([]byte, error) {
	if executor == nil || ctx == nil || name == "" {
		return nil, ErrSecretReferenceInvalid
	}
	request := secretIORequest{ctx: ctx, name: name, result: make(chan secretIOResult, 1)}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-executor.stop:
		return nil, ErrSecretReferenceInvalid
	case executor.requests <- request:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-executor.stop:
		return nil, ErrSecretReferenceInvalid
	case result := <-request.result:
		return result.contents, result.err
	}
}

func (executor *secretIOExecutor) Close() {
	if executor == nil {
		return
	}
	executor.once.Do(func() { close(executor.stop) })
	executor.workers.Wait()
}

func (executor *secretIOExecutor) run() {
	defer executor.workers.Done()
	for {
		select {
		case <-executor.stop:
			return
		case request := <-executor.requests:
			select {
			case <-request.ctx.Done():
				request.result <- secretIOResult{err: request.ctx.Err()}
				continue
			default:
			}
			contents, err := executor.read(request.name)
			request.result <- secretIOResult{contents: contents, err: err}
		}
	}
}
