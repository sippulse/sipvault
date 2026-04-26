package capture

import "sync"

// MultiSource merges events from multiple Sources into a single channel.
type MultiSource struct {
	sources []Source
	events  chan CaptureEvent
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewMultiSource creates a MultiSource that fans-in events from all provided
// Sources into one channel.
func NewMultiSource(sources ...Source) *MultiSource {
	m := &MultiSource{
		sources: sources,
		events:  make(chan CaptureEvent, 256),
		done:    make(chan struct{}),
	}

	for _, src := range sources {
		m.wg.Add(1)
		go m.forward(src)
	}

	// Close the merged channel once all forwarders are done.
	go func() {
		m.wg.Wait()
		close(m.events)
	}()

	return m
}

// Events returns a read-only channel that receives events from all sources.
func (m *MultiSource) Events() <-chan CaptureEvent {
	return m.events
}

// Close signals all forwarders to stop and closes all underlying sources.
func (m *MultiSource) Close() error {
	select {
	case <-m.done:
		// Already closed.
		return nil
	default:
		close(m.done)
	}

	var firstErr error
	for _, src := range m.sources {
		if err := src.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	m.wg.Wait()
	return firstErr
}

func (m *MultiSource) forward(src Source) {
	defer m.wg.Done()

	ch := src.Events()
	for {
		select {
		case <-m.done:
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			select {
			case m.events <- ev:
			case <-m.done:
				return
			}
		}
	}
}
