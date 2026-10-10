package main

import (
	"context"
	"time"
)

const guestCutoverTimeout = 5 * time.Second

// runGuestCutover drives a registered listener through its announcement and
// live API cutover phases. The caller owns the listener registration.
func runGuestCutover(listenerCtx context.Context, receive func(context.Context) error, fire func(context.Context), finished func()) {
	defer finished() // Keep the per-Port registration through API completion.
	if err := receive(listenerCtx); err != nil || listenerCtx.Err() != nil {
		return
	}
	apiCtx, cancel := context.WithTimeout(listenerCtx, guestCutoverTimeout)
	defer cancel()
	fire(apiCtx)
}
