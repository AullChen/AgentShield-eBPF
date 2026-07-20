// SPDX-License-Identifier: Dual MIT/GPL
#ifndef AGENTSHIELD_MAPS_H
#define AGENTSHIELD_MAPS_H

#include "events.h"

#define AGENTSHIELD_MAX_SCOPES 1024
#define AGENTSHIELD_STATS_SLOTS 32
#define AGENTSHIELD_RINGBUF_SIZE (1 << 20)

enum agentshield_stat_base {
	AGENTSHIELD_STAT_EVENTS_TOTAL_BASE = 0,
	AGENTSHIELD_STAT_EVENTS_DROPPED_BASE = 16,
};

struct agentshield_scope_value {
	__u64 instance_id;
	__u64 scope_cookie;
	__u32 profile_id;
	__u32 reserved;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, AGENTSHIELD_RINGBUF_SIZE);
} agentshield_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, AGENTSHIELD_MAX_SCOPES);
	__type(key, __u64);
	__type(value, struct agentshield_scope_value);
} agentshield_scope_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, AGENTSHIELD_STATS_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} agentshield_stats_map SEC(".maps");

#endif // AGENTSHIELD_MAPS_H
