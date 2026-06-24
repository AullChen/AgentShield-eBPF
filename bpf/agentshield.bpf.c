// SPDX-License-Identifier: Dual MIT/GPL

#ifdef AGENTSHIELD_BPF_SYNTAX_CHECK
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27

static __u64 bpf_ktime_get_ns(void) { return 0; }
static __u64 bpf_get_current_pid_tgid(void) { return 0; }
static __u64 bpf_get_current_uid_gid(void) { return 0; }
static __u64 bpf_get_current_cgroup_id(void) { return 0; }
static int bpf_get_current_comm(void *buf, __u32 size) { return 0; }
static void *bpf_map_lookup_elem(void *map, const void *key) { return 0; }
#else
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#endif

#include "events.h"
#include "maps.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const volatile __u16 agentshield_schema_version =
	AGENTSHIELD_EVENT_SCHEMA_VERSION;

static __always_inline int agentshield_current_scope(__u64 *cgroup_id,
						     __u32 *profile_id)
{
	__u32 *found;

	*cgroup_id = bpf_get_current_cgroup_id();
	found = bpf_map_lookup_elem(&agentshield_scope_map, cgroup_id);
	if (!found)
		return 0;

	*profile_id = *found;
	return 1;
}

static __always_inline void
agentshield_fill_common(struct agentshield_event *event, __u16 event_type,
			__u64 cgroup_id, __u32 profile_id)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	event->schema_version = AGENTSHIELD_EVENT_SCHEMA_VERSION;
	event->event_type = event_type;
	event->action = AGENTSHIELD_ACTION_AUDIT;
	event->action_result = AGENTSHIELD_RESULT_ALLOWED;
	event->timestamp_ns = bpf_ktime_get_ns();
	event->cgroup_id = cgroup_id;
	event->pid = pid_tgid >> 32;
	event->tgid = (__u32)pid_tgid;
	event->ppid = 0;
	event->uid = (__u32)uid_gid;
	event->profile_id = profile_id;
	event->policy_id = 0;
	event->rule_id = 0;
	event->flags = 0;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
}
