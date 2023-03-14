package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type Indexer struct {
	Kind      client.Object
	Name      string
	Extractor client.IndexerFunc
}

func addIndexer(ctx context.Context, mgr manager.Manager, indexer Indexer) error {
	return mgr.GetFieldIndexer().IndexField(ctx, indexer.Kind, indexer.Name, indexer.Extractor)
}

func addIndexers(ctx context.Context, mgr manager.Manager, indexers ...Indexer) error {
	for _, indexer := range indexers {
		if err := addIndexer(ctx, mgr, indexer); err != nil {
			return err
		}
	}
	return nil
}
