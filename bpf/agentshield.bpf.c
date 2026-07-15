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
static void *bpf_get_current_task_btf(void) { return 0; }
static int bpf_get_current_comm(void *buf, __u32 size) { return 0; }
static void *bpf_map_lookup_elem(void *map, const void *key) { return 0; }
static void *bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags)
{
	return 0;
}
static void bpf_ringbuf_submit(void *data, __u64 flags) {}
static long bpf_probe_read_user_str(void *dst, __u32 size, const void *unsafe_ptr)
{
	return 0;
}
static long bpf_probe_read_user(void *dst, __u32 size, const void *unsafe_ptr)
{
	return 0;
}
static __u16 bpf_ntohs(__u16 value) { return __builtin_bswap16(value); }

struct task_struct {
	struct task_struct *real_parent;
	__u32 tgid;
};

#define BPF_CORE_READ(source, field1, field2) ((source)->field1->field2)

struct trace_event_raw_sys_enter {
	long id;
	unsigned long long args[6];
};

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 protocol;
};
#else
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
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
			__u64 cgroup_id, __u32 profile_id, __u32 ppid)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	event->schema_version = AGENTSHIELD_EVENT_SCHEMA_VERSION;
	event->event_type = event_type;
	event->action = AGENTSHIELD_ACTION_AUDIT;
	event->action_result = AGENTSHIELD_RESULT_NONE;
	event->timestamp_ns = bpf_ktime_get_ns();
	event->cgroup_id = cgroup_id;
	event->pid = (__u32)pid_tgid;
	event->tgid = pid_tgid >> 32;
	event->ppid = ppid;
	event->uid = (__u32)uid_gid;
	event->profile_id = profile_id;
	event->policy_id = 0;
	event->rule_id = 0;
	event->flags = 0;
	event->syscall_flags = 0;
	event->captured_argc_plus_one = 0;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

static __always_inline __u32 agentshield_current_ppid(void)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return BPF_CORE_READ(task, real_parent, tgid);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int agentshield_trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct agentshield_event *event;
	const char *filename = (const char *)ctx->args[0];
	const char *const *argv = (const char *const *)ctx->args[1];
	const char *arg = 0;
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u32 profile_id = 0;
	long read_len;
	__u32 captured_argc = 0;
	int i;

	event = bpf_ringbuf_reserve(&agentshield_events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	agentshield_fill_common(event, AGENTSHIELD_EVENT_EXEC_ATTEMPT,
				cgroup_id, profile_id, agentshield_current_ppid());

	read_len = bpf_probe_read_user_str(event->data,
					   AGENTSHIELD_EXEC_EXE_LEN, filename);
	if (read_len < 0 || read_len == AGENTSHIELD_EXEC_EXE_LEN)
		event->flags |= AGENTSHIELD_FLAG_TRUNCATED;

#pragma unroll
	for (i = 0; i < AGENTSHIELD_EXEC_ARG_COUNT; i++) {
		arg = 0;
		if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) < 0) {
			event->flags |= AGENTSHIELD_FLAG_TRUNCATED;
			break;
		}
		if (!arg)
			break;

		read_len = bpf_probe_read_user_str(
			&event->data[AGENTSHIELD_EXEC_EXE_LEN +
				     i * AGENTSHIELD_EXEC_ARG_LEN],
			AGENTSHIELD_EXEC_ARG_LEN, arg);
		if (read_len < 0) {
			event->flags |= AGENTSHIELD_FLAG_TRUNCATED;
			break;
		}
		captured_argc++;
		if (read_len == AGENTSHIELD_EXEC_ARG_LEN)
			event->flags |= AGENTSHIELD_FLAG_TRUNCATED;
	}
	event->captured_argc_plus_one = captured_argc + 1;

	if (captured_argc == AGENTSHIELD_EXEC_ARG_COUNT) {
		arg = 0;
		if (bpf_probe_read_user(&arg, sizeof(arg),
					&argv[AGENTSHIELD_EXEC_ARG_COUNT]) < 0 || arg)
			event->flags |= AGENTSHIELD_FLAG_TRUNCATED;
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int agentshield_trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct agentshield_event *event;
	const char *filename;
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u32 profile_id = 0;
	long read_len;

	event = bpf_ringbuf_reserve(&agentshield_events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	agentshield_fill_common(event, AGENTSHIELD_EVENT_FILE_OPEN, cgroup_id,
				profile_id, agentshield_current_ppid());

	filename = (const char *)ctx->args[1];
	event->syscall_flags = (__u32)ctx->args[2];
	read_len = bpf_probe_read_user_str(event->data, sizeof(event->data),
					   filename);
	if (read_len < 0 || read_len == sizeof(event->data))
		event->flags |= AGENTSHIELD_FLAG_TRUNCATED;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int
agentshield_audit_connect(struct bpf_sock_addr *ctx, __u16 address_family)
{
	struct agentshield_network_payload *payload;
	struct agentshield_event *event;
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u32 profile_id = 0;
	if (ctx->protocol != AGENTSHIELD_IPPROTO_TCP)
		return 1;

	event = bpf_ringbuf_reserve(&agentshield_events, sizeof(*event), 0);
	if (!event)
		return 1;

	__builtin_memset(event, 0, sizeof(*event));
	agentshield_fill_common(event, AGENTSHIELD_EVENT_NET_CONNECT, cgroup_id,
				profile_id, 0);
	event->flags |= AGENTSHIELD_FLAG_FIELD_UNAVAILABLE;

	payload = (struct agentshield_network_payload *)event->data;
	payload->destination_port = bpf_ntohs((__u16)ctx->user_port);
	payload->address_family = address_family;
	payload->protocol = AGENTSHIELD_IPPROTO_TCP;
	if (address_family == AGENTSHIELD_AF_INET)
		__builtin_memcpy(payload->destination_address, &ctx->user_ip4,
				 sizeof(ctx->user_ip4));
	else
		__builtin_memcpy(payload->destination_address, &ctx->user_ip6,
				 sizeof(ctx->user_ip6));

	bpf_ringbuf_submit(event, 0);
	return 1;
}

SEC("cgroup/connect4")
int agentshield_connect4(struct bpf_sock_addr *ctx)
{
	return agentshield_audit_connect(ctx, AGENTSHIELD_AF_INET);
}

SEC("cgroup/connect6")
int agentshield_connect6(struct bpf_sock_addr *ctx)
{
	return agentshield_audit_connect(ctx, AGENTSHIELD_AF_INET6);
}
