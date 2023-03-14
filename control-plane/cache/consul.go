package cache

import (
	"context"
	"errors"
	"sync"

	"github.com/go-logr/logr"
	"github.com/hashicorp/consul-k8s/control-plane/consul"
	"github.com/hashicorp/consul/api"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

var ErrStaleEntry = errors.New("entry is stale")

const namespaceWildcard = "*"

type synthesizedObject struct {
	client.Object // dummy

	types.NamespacedName
}

var _ client.Object = (*synthesizedObject)(nil)

func newSynthesizedObject(namespacedName types.NamespacedName) *synthesizedObject {
	return &synthesizedObject{
		NamespacedName: namespacedName,
	}
}

func (s *synthesizedObject) GetName() string {
	return s.NamespacedName.Name
}

func (s *synthesizedObject) GetNamespace() string {
	return s.NamespacedName.Namespace
}

type Transformer func(api.ConfigEntry) []types.NamespacedName

type Subscription interface {
	Cancel()
	Events() chan event.GenericEvent
}

type Config struct {
	ConsulClientConfig  *consul.Config
	ConsulServerConnMgr consul.ServerConnectionManager
	NamespacesEnabled   bool
	Partition           string
	Kinds               []string
	Logger              logr.Logger
}

type subscription struct {
	transformer Transformer
	ctx         context.Context
	cancel      context.CancelFunc
	events      chan event.GenericEvent
}

func (s *subscription) Cancel() {
	s.cancel()
}

func (s *subscription) Events() chan event.GenericEvent {
	return s.events
}

type resourceCache map[api.ResourceReference]api.ConfigEntry

func (r resourceCache) diff(cache resourceCache) []api.ConfigEntry {
	diff := []api.ConfigEntry{}

	for ref, entry := range cache {
		old, ok := r[ref]
		if !ok {
			diff = append(diff, entry)
		}
		if old.GetModifyIndex() < entry.GetModifyIndex() {
			diff = append(diff, entry)
		}
	}

	// pick up all the deleted entries
	for _, entry := range r {
		diff = append(diff, entry)
	}

	return diff
}

// Cache reads subscribes to and caches Consul objects.
type Cache struct {
	config    *consul.Config
	serverMgr consul.ServerConnectionManager
	log       logr.Logger

	cache      map[string]resourceCache
	cacheMutex sync.RWMutex

	subscribers     map[string][]*subscription
	subscriberMutex sync.Mutex

	partition     string
	useNamespaces bool

	synced chan struct{}

	kinds []string
}

// New
func New(config Config) *Cache {
	cache := make(map[string]resourceCache)
	for _, kind := range config.Kinds {
		cache[kind] = make(resourceCache)
	}

	return &Cache{
		config:        config.ConsulClientConfig,
		serverMgr:     config.ConsulServerConnMgr,
		useNamespaces: config.NamespacesEnabled,
		partition:     config.Partition,
		cache:         cache,
		kinds:         config.Kinds,
		synced:        make(chan struct{}, len(config.Kinds)),
		log:           config.Logger,
	}
}

// WaitSynced
func (c *Cache) WaitSynced(ctx context.Context) {
	for n := len(c.kinds); n > 0; n-- {
		select {
		case <-c.synced:
		case <-ctx.Done():
			return
		}
	}
}

// Subscribe
func (c *Cache) Subscribe(ctx context.Context, kind string, transformer Transformer) Subscription {
	c.subscriberMutex.Lock()
	defer c.subscriberMutex.Unlock()

	subscribers, ok := c.subscribers[kind]
	if !ok {
		subscribers = []*subscription{}
	}
	ctx, cancel := context.WithCancel(ctx)
	events := make(chan event.GenericEvent)
	subscription := &subscription{
		ctx:         ctx,
		cancel:      cancel,
		events:      events,
		transformer: transformer,
	}

	subscribers = append(subscribers, subscription)
	c.subscribers[kind] = subscribers

	return subscription
}

func (c *Cache) Write(entry api.ConfigEntry) error {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	client, err := consul.NewClientFromConnMgr(c.config, c.serverMgr)
	if err != nil {
		return err
	}

	options := &api.WriteOptions{}
	if c.useNamespaces {
		options.Namespace = namespaceWildcard
	}
	if c.partition != "" {
		options.Partition = c.partition
	}

	updated, _, err := client.ConfigEntries().CAS(entry, entry.GetModifyIndex(), options)
	if err != nil {
		return err
	}
	if !updated {
		return ErrStaleEntry
	}

	return nil
}

func (c *Cache) Get(reference api.ResourceReference) api.ConfigEntry {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	resources, ok := c.cache[reference.Kind]
	if !ok {
		return nil
	}

	stored, ok := resources[reference]
	if !ok {
		return nil
	}

	return stored
}

// Run
func (c *Cache) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := range c.kinds {
		kind := c.kinds[i]

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.subscribeConsul(ctx, kind)
		}()
	}

	wg.Wait()
}

func (c *Cache) subscribeConsul(ctx context.Context, kind string) {
	once := &sync.Once{}

	options := &api.QueryOptions{}
	if c.useNamespaces {
		options.Namespace = namespaceWildcard
	}
	if c.partition != "" {
		options.Partition = c.partition
	}

	for {
		client, err := consul.NewClientFromConnMgr(c.config, c.serverMgr)
		if err != nil {
			c.log.Error(err, "error initializing consul client")
			continue
		}

		entries, meta, err := client.ConfigEntries().List(kind, options)
		if err != nil {
			c.log.Error(err, "error fetching config entries")
			continue
		}
		options.WaitIndex = meta.LastIndex

		c.updateAndNotify(ctx, once, kind, entries)

		select {
		case <-ctx.Done():
			return
		default:
			continue
		}
	}
}

func (c *Cache) updateAndNotify(ctx context.Context, once *sync.Once, kind string, entries []api.ConfigEntry) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	cache := make(resourceCache)
	for _, entry := range entries {
		cache[entryToReference(entry)] = entry
	}

	diff := c.cache[kind].diff(cache)

	// we've filled the cache once, notify the waiter
	once.Do(func() {
		c.synced <- struct{}{}
	})

	// now notify any subscribers
	c.notifySubscribers(ctx, kind, diff)
}

func (c *Cache) notifySubscribers(ctx context.Context, kind string, entries []api.ConfigEntry) {
	c.subscriberMutex.Lock()
	defer c.subscriberMutex.Unlock()

	for _, entry := range entries {
		subscribers := []*subscription{}
		for _, subscriber := range c.subscribers[kind] {
			addSubscriber := false
			for _, request := range subscriber.transformer(entry) {
				event := event.GenericEvent{Object: newSynthesizedObject(request)}

				select {
				case <-ctx.Done():
					return
				case <-subscriber.ctx.Done():
					// don't add the subscriber to the filtered subscribers, so it can be GC'd
					addSubscriber = false
				case subscriber.events <- event:
					// keep this one around
					addSubscriber = true
				}
			}

			if addSubscriber {
				subscribers = append(subscribers, subscriber)
			}
		}
		c.subscribers[kind] = subscribers
	}
}

func entryToReference(entry api.ConfigEntry) api.ResourceReference {
	return api.ResourceReference{
		Kind:      entry.GetKind(),
		Name:      entry.GetName(),
		Namespace: entry.GetNamespace(),
		Partition: entry.GetPartition(),
	}
}
