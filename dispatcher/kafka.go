package dispatcher

import (
	"alertkick-poller/client"
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
)

// KafkaDispatcher consumes pre-scheduled assignments from a regional topic.
// Apapi's dispatcher has already decided "monitor X is due now at location Y",
// so each Kafka message is a single assignment ready to execute — there's no
// local scheduling layer.
type KafkaDispatcher struct {
	reader *kafka.Reader
}

// NewKafkaDispatcher builds a consumer-group reader against the given
// regional assignments topic.
func NewKafkaDispatcher(brokers []string, topic, groupID string) *KafkaDispatcher {
	return &KafkaDispatcher{
		reader: kafka.NewReader(kafka.ReaderConfig{
			Brokers:        brokers,
			Topic:          topic,
			GroupID:        groupID,
			MinBytes:       1,
			MaxBytes:       10 * 1024 * 1024, // 10MiB per fetch
			MaxWait:        500 * time.Millisecond,
			CommitInterval: time.Second,
		}),
	}
}

func (d *KafkaDispatcher) Run(ctx context.Context, out chan<- *client.MonitorAssignment) error {
	log.Printf("[dispatcher/kafka] consuming topic=%s group=%s", d.reader.Config().Topic, d.reader.Config().GroupID)
	for {
		msg, err := d.reader.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			// Transient read errors: log and back off briefly so we don't
			// hot-loop against a broker outage.
			log.Printf("[dispatcher/kafka] read error: %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
				continue
			}
		}

		var m client.MonitorAssignment
		if err := json.Unmarshal(msg.Value, &m); err != nil {
			log.Printf("[dispatcher/kafka] malformed assignment at offset %d: %v", msg.Offset, err)
			continue
		}
		// Producer timestamp — dispatch lag is measured from when the api
		// decided the check was due, not from local receipt.
		m.ReceivedAt = msg.Time
		if m.ReceivedAt.IsZero() {
			m.ReceivedAt = time.Now()
		}

		select {
		case <-ctx.Done():
			return nil
		case out <- &m:
		}
	}
}

// Close stops the consumer group session and releases partitions cleanly.
func (d *KafkaDispatcher) Close() error {
	return d.reader.Close()
}
