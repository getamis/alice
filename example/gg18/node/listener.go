package node

import (
	"fmt"

	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type Listener interface {
	types.StateChangedListener

	Done() <-chan error
}

func NewListener() *listener {
	return &listener{
		errCh: make(chan error, 1),
	}
}

type listener struct {
	errCh chan error
}

func (l *listener) OnStateChanged(oldState types.MainState, newState types.MainState) {
	if newState == types.StateFailed {
		l.errCh <- fmt.Errorf("State %s -> %s", oldState.String(), newState.String())
		return
	} else if newState == types.StateDone {
		l.errCh <- nil
		return
	}

	log.Debug("State changed", "old", oldState.String(), "new", newState.String())
}

func (l *listener) Done() <-chan error {
	return l.errCh
}
