package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
)

func readFlowStream(parent context.Context, out chan<- flowRecord, stream func(context.Context, io.Writer) error) error {
	ctx, cancel := context.WithCancel(parent)
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := stream(ctx, pw)
		_ = pw.CloseWithError(err)
	}()
	stop := context.AfterFunc(ctx, func() { _ = pr.CloseWithError(ctx.Err()) })
	defer func() {
		stop()
		cancel()
		_ = pr.Close()
		<-done
	}()
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var r flowRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			select {
			case out <- r:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return sc.Err()
}
