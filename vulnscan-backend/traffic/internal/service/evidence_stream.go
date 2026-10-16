package service

import (
	"context"
	"fmt"
	"reflect"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

const snapshotStreamVersion = "snapshot-stream-1"
const snapshotPageBytes = int64(2 << 20)
const snapshotRowBytes = int64(2 << 20)
const snapshotTotalBytes = int64(512 << 20)
const snapshotFeatureBytes = int64(32 << 20)

func snapshotBoundedPage(ctx context.Context, st store.Store, q store.HitQuery, rw int64) ([]store.Hit, error) {
	if reader, ok := st.(store.SnapshotPageReader); ok {
		return reader.SnapshotPage(ctx, q, rw, snapshotPageBytes, snapshotRowBytes)
	}
	// Stores without a byte-aware reader may only supply one row per call.
	q.Limit = 1
	page, err := snapshotHitPage(ctx, st, q, rw)
	if err != nil {
		return nil, err
	}
	for _, h := range page {
		if int64(len(h.Raw)) > snapshotRowBytes {
			return nil, fmt.Errorf("snapshot_row_budget_exceeded:%s", h.ID)
		}
	}
	return page, nil
}

// Charge newly retained feature values, never the discarded raw JSON. Charging
// aliased values twice is conservative and keeps the retained budget explicit.
func snapshotFeatureCharge(values ...any) int64 {
	var total int64
	for _, v := range values {
		total += retainedFeatureSize(reflect.ValueOf(v))
	}
	return total
}

// Charge struct/slice storage and referenced strings, including duplicate
// references conservatively. JSON field names are not retained allocations.
// Page/raw decode and bounded semantic reservoirs have separate budgets.
func retainedFeatureSize(v reflect.Value) int64 {
	if !v.IsValid() {
		return 0
	}
	n := int64(v.Type().Size())
	switch v.Kind() {
	case reflect.String:
		return n + int64(v.Len())
	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			n += retainedFeatureSize(v.Elem())
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			n += retainedFeatureSize(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			n += retainedFeatureSize(v.Field(i)) - int64(v.Field(i).Type().Size())
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			n += 64 + retainedFeatureSize(it.Key()) + retainedFeatureSize(it.Value())
		}
	}
	return n
}

type featureMark struct{ http, dns, records, bindings, contacts, semantic int }

func snapshotFeatureMark(in *evidence.Input, p *PhaseOneMaterials, sem int) featureMark {
	m := featureMark{semantic: sem}
	if in.HTTP != nil {
		m.http = len(in.HTTP.Records)
	}
	if in.DNS != nil {
		m.dns = len(in.DNS.Records)
	}
	if p != nil {
		m.records = len(p.Records)
		m.bindings = len(p.Bindings)
		m.contacts = len(p.Contacts)
	}
	return m
}
func snapshotFeatureDelta(in *evidence.Input, out *SnapshotEvidenceInput, m featureMark, hit evidence.Hit) int64 {
	n := snapshotFeatureCharge(hit, hit) // request and scope timeline metadata
	// Enrichment may remove the current metadata projection; prior records remain.
	if in.HTTP != nil && len(in.HTTP.Records) > m.http {
		n += snapshotFeatureCharge(in.HTTP.Records[m.http:])
	}
	if in.DNS != nil && len(in.DNS.Records) > m.dns {
		n += snapshotFeatureCharge(in.DNS.Records[m.dns:])
	}
	if p := out.Manifest.PhaseOne; p != nil {
		n += snapshotFeatureCharge(p.Records[m.records:], p.Bindings[m.bindings:], p.Contacts[m.contacts:])
	}
	if len(out.SemanticObservations) > m.semantic {
		n += snapshotFeatureCharge(out.SemanticObservations[m.semantic:])
	}
	return n
}
