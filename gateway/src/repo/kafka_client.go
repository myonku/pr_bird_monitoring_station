package repo

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"

	modelsystem "gateway/src/models/system"
)

// KafkaClient 封装生产、消费和 topic 管理等常见操作。
type KafkaClient struct {
	brokers      []string
	dialer       *kafka.Dialer
	batchTimeout time.Duration
	requiredAcks kafka.RequiredAcks
	opTimeout    time.Duration

	mu      sync.Mutex
	writers map[string]*kafka.Writer
	readers map[string]*kafka.Reader
}

// NewKafkaClient 创建并验证 Kafka 连接。
func NewKafkaClient(cfg *modelsystem.KafkaClientConfig) (*KafkaClient, error) {
	if len(cfg.Brokers) == 0 {
		return nil, &modelsystem.ErrBrokersRequired
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = 5 * time.Second
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 50 * time.Millisecond
	}

	dialer := &kafka.Dialer{
		ClientID: cfg.ClientID,
		Timeout:  cfg.DialTimeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.OpTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Brokers[0])
	if err != nil {
		return nil, err
	}
	_ = conn.Close()

	return &KafkaClient{
		brokers:      cfg.Brokers,
		dialer:       dialer,
		batchTimeout: cfg.BatchTimeout,
		requiredAcks: cfg.RequiredAcks,
		opTimeout:    cfg.OpTimeout,
		writers:      make(map[string]*kafka.Writer),
		readers:      make(map[string]*kafka.Reader),
	}, nil
}

// Close 关闭所有复用的 reader/writer。
func (c *KafkaClient) Close() error {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	for key, writer := range c.writers {
		if err := writer.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close writer %s: %w", key, err)
		}
	}
	for key, reader := range c.readers {
		if err := reader.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close reader %s: %w", key, err)
		}
	}

	c.writers = make(map[string]*kafka.Writer)
	c.readers = make(map[string]*kafka.Reader)
	return firstErr
}

// WriteMessages 批量发送消息。
func (c *KafkaClient) WriteMessages(ctx context.Context, topic string, messages ...kafka.Message) error {
	if topic == "" {
		return &modelsystem.ErrTopicRequired
	}
	writer, err := c.getOrCreateWriter(topic)
	if err != nil {
		return err
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return writer.WriteMessages(ctx, messages...)
}

// WriteKeyValue 发送单条 key/value 消息。
func (c *KafkaClient) WriteKeyValue(
	ctx context.Context, topic string, key, value []byte, headers map[string]string) error {
	msg := kafka.Message{Key: key, Value: value}
	if len(headers) > 0 {
		msg.Headers = make([]kafka.Header, 0, len(headers))
		for k, v := range headers {
			msg.Headers = append(msg.Headers, kafka.Header{Key: k, Value: []byte(v)})
		}
	}
	return c.WriteMessages(ctx, topic, msg)
}

// CreateReader 创建并复用 consumer group reader。
func (c *KafkaClient) CreateReader(topic, groupID string, minBytes, maxBytes int) (*kafka.Reader, error) {
	if topic == "" {
		return nil, &modelsystem.ErrTopicRequired
	}
	if groupID == "" {
		return nil, &modelsystem.ErrGroupIDRequired
	}
	if minBytes <= 0 {
		minBytes = 10e3
	}
	if maxBytes <= 0 {
		maxBytes = 10e6
	}

	key := readerKey(topic, groupID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.readers[key]; ok {
		return existing, nil
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  c.brokers,
		GroupID:  groupID,
		Topic:    topic,
		MinBytes: minBytes,
		MaxBytes: maxBytes,
		Dialer:   c.dialer,
	})
	c.readers[key] = reader
	return reader, nil
}

// ReadMessage 读取并自动提交单条消息。
func (c *KafkaClient) ReadMessage(ctx context.Context, topic, groupID string) (kafka.Message, error) {
	reader, err := c.CreateReader(topic, groupID, 0, 0)
	if err != nil {
		return kafka.Message{}, err
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return reader.ReadMessage(ctx)
}

// FetchMessage 拉取但不提交单条消息。
func (c *KafkaClient) FetchMessage(ctx context.Context, topic, groupID string) (kafka.Message, error) {
	reader, err := c.CreateReader(topic, groupID, 0, 0)
	if err != nil {
		return kafka.Message{}, err
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return reader.FetchMessage(ctx)
}

// CommitMessages 手动提交消息位点。
func (c *KafkaClient) CommitMessages(
	ctx context.Context, topic, groupID string, messages ...kafka.Message) error {

	reader, err := c.CreateReader(topic, groupID, 0, 0)
	if err != nil {
		return err
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return reader.CommitMessages(ctx, messages...)
}

// CreateTopic 创建 topic。
func (c *KafkaClient) CreateTopic(
	ctx context.Context, topic string, partitions, replicationFactor int) error {
	if topic == "" {
		return &modelsystem.ErrTopicRequired
	}
	if partitions <= 0 {
		partitions = 1
	}
	if replicationFactor <= 0 {
		replicationFactor = 1
	}

	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	controllerConn, err := c.dialController(ctx)
	if err != nil {
		return err
	}
	defer controllerConn.Close()

	return controllerConn.CreateTopics(kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     partitions,
		ReplicationFactor: replicationFactor,
	})
}

// DeleteTopic 删除 topic。
func (c *KafkaClient) DeleteTopic(ctx context.Context, topic string) error {
	if topic == "" {
		return &modelsystem.ErrTopicRequired
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	controllerConn, err := c.dialController(ctx)
	if err != nil {
		return err
	}
	defer controllerConn.Close()

	return controllerConn.DeleteTopics(topic)
}

// ListTopicPartitions 列出集群中所有 partition 信息。
func (c *KafkaClient) ListTopicPartitions(ctx context.Context) ([]kafka.Partition, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()

	conn, err := c.dialBroker(ctx, c.brokers[0])
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ReadPartitions()
}

// Ping 探测 broker 可用性。
func (c *KafkaClient) Ping(ctx context.Context) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	conn, err := c.dialBroker(ctx, c.brokers[0])
	if err != nil {
		return err
	}
	return conn.Close()
}

// getOrCreateWriter 获取或创建 topic 对应的 writer。
func (c *KafkaClient) getOrCreateWriter(topic string) (*kafka.Writer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if writer, ok := c.writers[topic]; ok {
		return writer, nil
	}

	writer := &kafka.Writer{
		Addr:         kafka.TCP(c.brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		BatchTimeout: c.batchTimeout,
		RequiredAcks: c.requiredAcks,
		Transport: &kafka.Transport{
			DialTimeout: c.dialer.Timeout,
		},
	}
	c.writers[topic] = writer
	return writer, nil
}

func (c *KafkaClient) dialBroker(ctx context.Context, address string) (*kafka.Conn, error) {
	return c.dialer.DialContext(ctx, "tcp", address)
}

func (c *KafkaClient) dialController(ctx context.Context) (*kafka.Conn, error) {
	conn, err := c.dialBroker(ctx, c.brokers[0])
	if err != nil {
		return nil, err
	}
	controller, err := conn.Controller()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.Close()

	return c.dialBroker(ctx, net.JoinHostPort(
		controller.Host, fmt.Sprint(controller.Port)))
}

func (c *KafkaClient) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.opTimeout <= 0 {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.opTimeout)
}

func readerKey(topic, groupID string) string {
	return topic + "::" + groupID
}
