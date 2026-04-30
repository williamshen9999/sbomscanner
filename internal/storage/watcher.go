package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/nats-io/nats.go"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/client-go/tools/cache"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// event is the payload sent via NATS for watch events.
type event struct {
	EventType watch.EventType      `json:"eventType"`
	Object    runtime.RawExtension `json:"object"`
}

// natsWatcher subscribes to NATS watch events and broadcasts them locally.
type natsWatcher struct {
	nc               *nats.Conn
	subject          string
	resource         string
	watchBroadcaster *watch.Broadcaster
	logger           *slog.Logger
	store            *store
}

func newNatsWatcher(nc *nats.Conn,
	resource string,
	watchBroadcaster *watch.Broadcaster,
	store *store,
	logger *slog.Logger,
) *natsWatcher {
	subject := fmt.Sprintf("watch.%s", resource)

	return &natsWatcher{
		nc:               nc,
		resource:         resource,
		subject:          subject,
		watchBroadcaster: watchBroadcaster,
		store:            store,
		logger:           logger.With("component", "nats-watcher", "subject", subject),
	}
}

// Start begins subscribing to NATS messages on the given subject.
func (w *natsWatcher) Start(ctx context.Context) error {
	sub, err := w.nc.Subscribe(w.subject, func(msg *nats.Msg) {
		if err := w.handleMessage(ctx, msg); err != nil {
			w.logger.ErrorContext(ctx, "Failed to handle NATS message",
				"error", err,
				"subject", msg.Subject,
			)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to NATS subject %s: %w", w.subject, err)
	}

	w.logger.InfoContext(ctx, "Watch broadcaster started", "subject", w.subject)

	<-ctx.Done()

	w.logger.InfoContext(ctx, "Shutting down watcher", "subject", w.subject)
	w.watchBroadcaster.Shutdown()
	if err := sub.Unsubscribe(); err != nil {
		w.logger.ErrorContext(ctx, "Failed to unsubscribe from NATS", "error", err)
	}

	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("context error while shutting down watcher: %w", err)
	}

	return nil
}

// handleMessage processes a NATS message and broadcasts it locally.
func (w *natsWatcher) handleMessage(ctx context.Context, msg *nats.Msg) error {
	var payload event
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	obj := w.store.newFunc()
	if err := json.Unmarshal(payload.Object.Raw, obj); err != nil {
		return fmt.Errorf("failed to decode object: %w", err)
	}

	// For deleted events broadcast the payload directly since the store no longer has it.
	// Otherwise rehydrate fields stripped by the publish-side transform (e.g. SBOM.SPDX) from the store's current state.
	if payload.EventType != watch.Deleted {
		rehydrated, err := w.rehydrate(ctx, obj)
		if err != nil {
			return err
		}
		obj = rehydrated
	}

	if err := w.watchBroadcaster.Action(payload.EventType, obj); err != nil {
		return fmt.Errorf("failed to broadcast action while handling message: %w", err)
	}

	w.logger.DebugContext(ctx, "Broadcasted watch event",
		"type", payload.EventType,
		"obj", payload.Object,
	)
	return nil
}

// rehydrate returns the stored object matching the payload, or the payload itself when the store does not hold a matching object.
// Falling back to the payload (rather than dropping the event) keeps downstream watchers like the GC dependency graph builder consistent. The following DELETED event reconciles client state.
func (w *natsWatcher) rehydrate(ctx context.Context, payloadObj runtime.Object) (runtime.Object, error) {
	payloadAccessor, err := meta.Accessor(payloadObj)
	if err != nil {
		return nil, fmt.Errorf("failed to get meta accessor: %w", err)
	}
	key := fmt.Sprintf("%s/%s/%s/%s", storagev1alpha1.GroupName, w.resource, payloadAccessor.GetNamespace(), payloadAccessor.GetName())

	fetched := w.store.newFunc()
	if err := w.store.Get(ctx, key, storage.GetOptions{}, fetched); err != nil {
		if !storage.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get object from store while handling message: %w", err)
		}
		w.logger.DebugContext(ctx, "Object not found in store while handling message; broadcasting payload",
			"key", key,
		)
		return payloadObj, nil
	}

	fetchedAccessor, err := meta.Accessor(fetched)
	if err != nil {
		return nil, fmt.Errorf("failed to get meta accessor for fetched object: %w", err)
	}
	if fetchedAccessor.GetUID() != payloadAccessor.GetUID() {
		// Same namespace/name, different object: it was deleted and recreated before we got here.
		w.logger.DebugContext(ctx, "Stored object UID does not match payload; broadcasting payload",
			"key", key,
			"payloadUID", payloadAccessor.GetUID(),
			"storedUID", fetchedAccessor.GetUID(),
		)
		return payloadObj, nil
	}

	return fetched, nil
}

// natsBroadcaster broadcasts watch events using NATS.
type natsBroadcaster struct {
	nc               *nats.Conn
	subject          string
	watchBroadcaster *watch.Broadcaster
	logger           *slog.Logger
	transform        cache.TransformFunc
}

func newNatsBroadcaster(nc *nats.Conn,
	resource string,
	watchBroadcaster *watch.Broadcaster,
	transform cache.TransformFunc,
	logger *slog.Logger,
) *natsBroadcaster {
	subject := fmt.Sprintf("watch.%s", resource)

	return &natsBroadcaster{
		nc:               nc,
		subject:          subject,
		watchBroadcaster: watchBroadcaster,
		transform:        transform,
		logger:           logger.With("component", "nats-broadcaster", "subject", subject),
	}
}

// Watch returns a watch.Interface that receives events from this broadcaster.
func (b *natsBroadcaster) Watch() (watch.Interface, error) {
	watch, err := b.watchBroadcaster.Watch()
	if err != nil {
		return nil, fmt.Errorf("failed to add new watcher: %w", err)
	}

	return watch, nil
}

// WatchWithPrefix returns a watch.Interface that receives a prefix of events.
func (b *natsBroadcaster) WatchWithPrefix(events []watch.Event) (watch.Interface, error) {
	watch, err := b.watchBroadcaster.WatchWithPrefix(events)
	if err != nil {
		return nil, fmt.Errorf("failed to add new watcher with prefix: %w", err)
	}

	return watch, nil
}

// Action broadcasts an event to all local watchers.
func (b *natsBroadcaster) Action(eventType watch.EventType, obj runtime.Object) error {
	t, err := b.transform(obj.DeepCopyObject())
	if err != nil {
		return fmt.Errorf("failed to transform object: %w", err)
	}
	transformedObj, ok := t.(runtime.Object)
	if !ok {
		return fmt.Errorf("transformed object is not a runtime.Object: %T", t)
	}

	objectBytes, err := json.Marshal(transformedObj)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	payload := event{
		EventType: eventType,
		Object:    runtime.RawExtension{Raw: objectBytes},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	if err := b.nc.Publish(b.subject, payloadBytes); err != nil {
		return fmt.Errorf("publish to NATS: %w", err)
	}

	b.logger.Debug("Published watch event to NATS", "eventType", eventType, "object", transformedObj)

	return nil
}
