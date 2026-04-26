package resultsink

import (
	"alertkick-poller/client"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
)

// KafkaResultSink produces one record per result, keyed by monitor UUID so
// consecutive results for a monitor land on the same partition (useful for
// downstream consumers that keep per-monitor state).
type KafkaResultSink struct {
	writer *kafka.Writer
}

func NewKafkaResultSink(brokers []string, topic string) *KafkaResultSink {
	return &KafkaResultSink{
		writer: &kafka.Writer{
			Addr:         kafka.TCP(brokers...),
			Topic:        topic,
			Balancer:     &kafka.Hash{},
			BatchTimeout: 50 * time.Millisecond,
			RequiredAcks: kafka.RequireAll, // wait for min.insync.replicas ack
			Async:        false,
		},
	}
}

func (s *KafkaResultSink) Submit(ctx context.Context, _ string, batch []client.CheckResult) (*SubmitStats, error) {
	if len(batch) == 0 {
		return &SubmitStats{}, nil
	}

	msgs := make([]kafka.Message, 0, len(batch))
	for i := range batch {
		r := &batch[i]
		payload, err := json.Marshal(r)
		if err != nil {
			// Shouldn't happen for a well-formed CheckResult — treat as rejected
			// rather than failing the whole batch.
			continue
		}
		msgs = append(msgs, kafka.Message{
			Key:   []byte(r.MonitorUUID),
			Value: payload,
		})
	}

	if err := s.writer.WriteMessages(ctx, msgs...); err != nil {
		return nil, fmt.Errorf("kafka produce: %w", err)
	}

	return &SubmitStats{Accepted: len(msgs), Rejected: len(batch) - len(msgs)}, nil
}

// Flush is a no-op for synchronous writers — WriteMessages already waits for
// ack before returning when Async=false.
func (s *KafkaResultSink) Flush(_ context.Context) error { return nil }

func (s *KafkaResultSink) Close() error { return s.writer.Close() }
