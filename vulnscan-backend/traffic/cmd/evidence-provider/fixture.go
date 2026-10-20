package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Only real Store row types are supported. Loading happens before querying an
// immutable MemoryStore; a whole PreparedBundle cannot be a provider response.
type platformFixture struct {
	Synthetic bool                    `json:"synthetic_fixture"`
	Events    []domain.Event          `json:"events"`
	Assets    []domain.Asset          `json:"assets"`
	Hits      []store.Hit             `json:"hits"`
	Records   []store.AggregateRecord `json:"records"`
}

func loadFixture(ctx context.Context, path string) (*store.MemoryStore, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var f platformFixture
	d := json.NewDecoder(file)
	d.DisallowUnknownFields()
	if err = d.Decode(&f); err != nil {
		return nil, err
	}
	if !f.Synthetic {
		return nil, fmt.Errorf("fixture_must_be_explicitly_synthetic")
	}
	s := store.NewMemoryStore()
	for _, e := range f.Events {
		if _, err = s.CreateEvent(e); err != nil {
			return nil, err
		}
	}
	for _, a := range f.Assets {
		if _, err = s.CreateAsset(a); err != nil {
			return nil, err
		}
	}
	for _, h := range f.Hits {
		if _, err = s.InsertHit(ctx, h); err != nil {
			return nil, err
		}
	}
	for _, r := range f.Records {
		if err = s.PutAggregateRecord(ctx, r); err != nil {
			return nil, err
		}
	}
	return s, nil
}
