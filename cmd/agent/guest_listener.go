package main

import "context"

// A listener owns both its context and its registration identity.
type guestAnnouncementListener struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (l *guestAnnouncementListener) run(watch func(context.Context) error) error {
	defer l.cancel()
	err := watch(l.ctx)
	if err == nil {
		return l.ctx.Err()
	}
	return err
}

// Called with the registration mutex held; only the current listener may fire.
func (l *guestAnnouncementListener) finish(running map[string]*guestAnnouncementListener, name string, err error) bool {
	if running[name] != l {
		return false
	}
	delete(running, name)
	return err == nil
}
