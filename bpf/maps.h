// SPDX-License-Identifier: Dual MIT/GPL
#ifndef AGENTSHIELD_MAPS_H
#define AGENTSHIELD_MAPS_H

#include "events.h"

#define AGENTSHIELD_MAX_SCOPES 1024
#define AGENTSHIELD_MAX_NETWORK_PROFILES 256
#define AGENTSHIELD_MAX_NETWORK_ALLOW_TUPLES 1024
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

enum agentshield_network_profile_flags {
	AGENTSHIELD_NETWORK_DEFAULT_DENY = 1 << 0,
};

enum agentshield_network_allow_flags {
	AGENTSHIELD_NETWORK_ALLOW_ANY_ADDRESS = 1 << 0,
	AGENTSHIELD_NETWORK_ALLOW_ANY_PORT = 1 << 1,
};

struct agentshield_network_profile {
	__u32 generation;
	__u32 policy_id;
	__u32 rule_id;
	__u32 flags;
};

struct agentshield_network_allow_key {
	__u32 profile_id;
	__u32 generation;
	__u16 address_family;
	__u16 destination_port;
	__u8 destination_address[16];
	__u32 match_flags;
};

_Static_assert(sizeof(struct agentshield_network_profile) == 16,
	       "network profile ABI size changed");
_Static_assert(sizeof(struct agentshield_network_allow_key) == 32,
	       "network allow key ABI size changed");

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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, AGENTSHIELD_MAX_NETWORK_PROFILES);
	__type(key, __u32);
	__type(value, struct agentshield_network_profile);
} agentshield_network_profile_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, AGENTSHIELD_MAX_NETWORK_ALLOW_TUPLES);
	__type(key, struct agentshield_network_allow_key);
	__type(value, __u8);
} agentshield_network_allow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, AGENTSHIELD_STATS_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} agentshield_stats_map SEC(".maps");

#endif // AGENTSHIELD_MAPS_H
