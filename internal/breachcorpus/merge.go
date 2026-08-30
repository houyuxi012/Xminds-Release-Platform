package breachcorpus

import (
	"bufio"
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const buildChunkBytes = 16 << 20

func writeSortedRun(runDirectory string, index int, entries []string) (string, error) {
	if len(entries) == 0 {
		return "", ErrBuildFailed
	}
	sort.Strings(entries)
	path := filepath.Join(runDirectory, runFileName(index))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", ErrBuildFailed
	}
	writer := bufio.NewWriter(file)
	var previous string
	for _, entry := range entries {
		if entry == previous {
			continue
		}
		if _, err := writer.WriteString(entry + "\n"); err != nil {
			_ = file.Close()
			return "", ErrBuildFailed
		}
		previous = entry
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		return "", ErrBuildFailed
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", ErrBuildFailed
	}
	if err := file.Close(); err != nil {
		return "", ErrBuildFailed
	}
	return path, nil
}

func runFileName(index int) string {
	const digits = 6
	value := make([]byte, digits)
	for position := digits - 1; position >= 0; position-- {
		value[position] = byte('0' + index%10)
		index /= 10
	}
	return "run-" + string(value) + ".txt"
}

type runCursor struct {
	file    *os.File
	scanner *bufio.Scanner
	value   string
	index   int
}

type cursorHeap []*runCursor

func (values cursorHeap) Len() int { return len(values) }

func (values cursorHeap) Less(left, right int) bool {
	if values[left].value == values[right].value {
		return values[left].index < values[right].index
	}
	return values[left].value < values[right].value
}

func (values cursorHeap) Swap(left, right int) {
	values[left], values[right] = values[right], values[left]
}
func (values *cursorHeap) Push(value any) { *values = append(*values, value.(*runCursor)) }

func (values *cursorHeap) Pop() any {
	previous := *values
	last := previous[len(previous)-1]
	*values = previous[:len(previous)-1]
	return last
}

func mergeRuns(runPaths []string, outputPath string, rawEntries uint64, maximumBytes int64) (Counts, int64, string, error) {
	var counts Counts
	if len(runPaths) == 0 || rawEntries == 0 || maximumBytes <= 0 || maximumBytes > MaximumCorpusBytes {
		return counts, 0, "", ErrBuildFailed
	}

	cursors := make([]*runCursor, 0, len(runPaths))
	defer func() {
		for _, cursor := range cursors {
			_ = cursor.file.Close()
		}
	}()

	values := make(cursorHeap, 0, len(runPaths))
	for index, path := range runPaths {
		file, err := os.Open(path)
		if err != nil {
			return counts, 0, "", ErrBuildFailed
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 128), 128)
		cursor := &runCursor{file: file, scanner: scanner, index: index}
		cursors = append(cursors, cursor)
		if !scanner.Scan() {
			return counts, 0, "", ErrBuildFailed
		}
		cursor.value = scanner.Text()
		values = append(values, cursor)
	}
	heap.Init(&values)

	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return counts, 0, "", ErrBuildFailed
	}
	outputOpen := true
	defer func() {
		if outputOpen {
			_ = output.Close()
		}
	}()

	hasher := sha256.New()
	writer := bufio.NewWriter(io.MultiWriter(output, hasher))
	var bytesWritten int64
	var previous string
	for values.Len() > 0 {
		cursor := heap.Pop(&values).(*runCursor)
		if cursor.value != previous {
			lineBytes := int64(len(cursor.value) + 1)
			if lineBytes > maximumBytes || bytesWritten > maximumBytes-lineBytes {
				return counts, 0, "", ErrBuildFailed
			}
			if _, err := writer.WriteString(cursor.value + "\n"); err != nil {
				return counts, 0, "", ErrBuildFailed
			}
			bytesWritten += lineBytes
			switch len(cursor.value) {
			case 40:
				counts.SHA1Entries++
			case 64:
				counts.SHA256Entries++
			default:
				return counts, 0, "", ErrBuildFailed
			}
			counts.UniqueEntries++
			previous = cursor.value
		}
		if cursor.scanner.Scan() {
			cursor.value = cursor.scanner.Text()
			heap.Push(&values, cursor)
		} else if cursor.scanner.Err() != nil {
			return counts, 0, "", ErrBuildFailed
		}
	}
	if counts.UniqueEntries == 0 || counts.UniqueEntries > rawEntries {
		return counts, 0, "", ErrBuildFailed
	}
	counts.DuplicateEntries = rawEntries - counts.UniqueEntries
	if err := writer.Flush(); err != nil {
		return counts, 0, "", ErrBuildFailed
	}
	if err := output.Sync(); err != nil {
		return counts, 0, "", ErrBuildFailed
	}
	if err := output.Close(); err != nil {
		return counts, 0, "", ErrBuildFailed
	}
	outputOpen = false
	return counts, bytesWritten, hex.EncodeToString(hasher.Sum(nil)), nil
}
