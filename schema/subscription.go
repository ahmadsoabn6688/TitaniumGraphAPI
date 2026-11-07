package schema

import (
	"fmt"
	"time"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
)

// Subscriptions (live queries).
//
// A role's Subscription root mirrors the read root fields of every table and
// native query it may subscribe to (select.subscribe: true): <t>_by_pk,
// <t>_connection, <t>_aggregate, the unique-key lookups <t>_by_<cols> and,
// for tables without a usable key, <t>_list; for native queries <q> and
// <q>_connection. Each one is the query field itself — same arguments, same
// resolver, same RBAC (columns, row filter, filter surface) — so a
// subscription can never read more than the matching query. The transport
// (server/ws.go) re-executes the operation on an interval with a fresh
// request context (relationship dataloaders, timeout, response limits) per
// tick, and pushes a result only when it differs from the last one sent.
//
// subscribe gates the root fields only: relationships selected below them
// follow the related table's select permission, as in queries.

// Built is the result of building every role's schema.
type Built struct {
	Schemas map[string]graphql.Schema
	// PollIntervals maps role -> subscription root field name -> polling
	// interval (only roles with a Subscription root appear).
	PollIntervals map[string]map[string]time.Duration
}

// Build builds one GraphQL schema per configured role, plus the polling
// intervals of their subscription fields.
func Build(opt Options) (*Built, error) {
	return buildAll(opt)
}

// subscriptionFields returns the role's Subscription root fields, copied
// from queryFields (after the root docs were applied, before custom fields
// can replace a generated one), and records each field's polling interval.
func (b *builder) subscriptionFields(queryFields graphql.Fields) graphql.Fields {
	subs := b.opt.Config.Server.Subscriptions
	if !subs.On() {
		return nil
	}
	def := subs.PollInterval()
	out := graphql.Fields{}
	b.pollIntervals = map[string]time.Duration{}
	add := func(name, kind string, polling *config.SubscriptionPolling) {
		f := queryFields[name]
		if name == "" || f == nil {
			return
		}
		every := polling.Interval(kind, def)
		cp := *f
		cp.Description = liveDescription(f.Description, every)
		out[name] = &cp
		b.pollIntervals[name] = every
	}

	for _, tn := range b.opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil || ti.access.Select == nil || !ti.access.Select.Subscribe {
			continue
		}
		var polling *config.SubscriptionPolling
		if tc := b.opt.Config.Tables[tn]; tc != nil {
			polling = tc.Subscriptions
		}
		add(ti.rootName(config.RootAggregate), config.RootAggregate, polling)
		for _, ul := range b.uniqueLookups(ti) {
			add(ul.names.query, config.SubscriptionUnique, polling)
		}
		if b.readKeyExposable(ti) {
			add(ti.rootName(config.RootByPK), config.RootByPK, polling)
			add(ti.rootName(config.RootConnection), config.RootConnection, polling)
		} else {
			add(b.shared.names.list[tn], config.RootList, polling)
		}
	}
	for _, qn := range b.shared.model.nativeOrder {
		ni := b.natives[qn]
		if ni == nil || ni.ti.access.Select == nil || !ni.ti.access.Select.Subscribe {
			continue
		}
		var polling *config.SubscriptionPolling
		if nq := b.opt.Config.NativeQueries[qn]; nq != nil {
			polling = nq.Subscriptions
		}
		add(ni.model.list.name, "list", polling)
		if ni.connType != nil {
			add(ni.model.conn.name, "connection", polling)
		}
	}
	return out
}

// liveDescription documents a subscription field: its query description
// plus how it is polled.
func liveDescription(desc string, every time.Duration) string {
	live := fmt.Sprintf("Live query: re-run every %s, pushed when the result changes.", every)
	if desc == "" {
		return live
	}
	return desc + "\n\n" + live
}
