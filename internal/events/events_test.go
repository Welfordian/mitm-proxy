package events

import "testing"

func TestSubscribeCancelRemovesSubscriber(t *testing.T) {
	bus := NewBus(4)
	ch, cancel := bus.Subscribe("*")

	bus.Publish(Event{Topic: TopicTrafficRequestStarted})
	select {
	case <-ch:
	default:
		t.Fatal("expected initial event")
	}

	cancel()
	cancel()
	bus.Publish(Event{Topic: TopicTrafficRequestStarted})
	select {
	case event := <-ch:
		t.Fatalf("received event after cancel: %+v", event)
	default:
	}
}
