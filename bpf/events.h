// SPDX-License-Identifier: Dual MIT/GPL
#ifndef AGENTSHIELD_EVENTS_H
#define AGENTSHIELD_EVENTS_H

#define AGENTSHIELD_EVENT_SCHEMA_VERSION 2
#define AGENTSHIELD_COMM_LEN 16
#define AGENTSHIELD_DATA_LEN 256
#define AGENTSHIELD_EXEC_EXE_LEN 128
#define AGENTSHIELD_EXEC_ARG_COUNT 4
#define AGENTSHIELD_EXEC_ARG_LEN 32
#define AGENTSHIELD_AF_INET 2
#define AGENTSHIELD_AF_INET6 10
#define AGENTSHIELD_IPPROTO_TCP 6

enum agentshield_event_type {
	AGENTSHIELD_EVENT_UNSPECIFIED = 0,
	AGENTSHIELD_EVENT_EXEC_ATTEMPT = 1,
	AGENTSHIELD_EVENT_FILE_OPEN = 2,
	AGENTSHIELD_EVENT_NET_CONNECT = 3,
	AGENTSHIELD_EVENT_POLICY_HIT = 4,
	AGENTSHIELD_EVENT_BLOCK_RESULT = 5,
	AGENTSHIELD_EVENT_DROP_NOTICE = 6,
	AGENTSHIELD_EVENT_SELF_DIAG = 7,
};

enum agentshield_action {
	AGENTSHIELD_ACTION_AUDIT = 0,
	AGENTSHIELD_ACTION_ALERT = 1,
	AGENTSHIELD_ACTION_BLOCK = 2,
	AGENTSHIELD_ACTION_CONTAIN = 3,
};

enum agentshield_action_result {
	AGENTSHIELD_RESULT_NONE = 0,
	AGENTSHIELD_RESULT_ALLOWED = 1,
	AGENTSHIELD_RESULT_BLOCKED = 2,
	AGENTSHIELD_RESULT_KILLED = 3,
	AGENTSHIELD_RESULT_FAILED = 4,
	/* Deprecated: use FALLBACK flag plus KILLED/FAILED result. */
	AGENTSHIELD_RESULT_FALLBACK = 5,
};

enum agentshield_event_flags {
	AGENTSHIELD_FLAG_TRUNCATED = 1 << 0,
	AGENTSHIELD_FLAG_FALLBACK = 1 << 1,
	AGENTSHIELD_FLAG_FIELD_UNAVAILABLE = 1 << 2,
};

struct agentshield_network_payload {
	__u8 destination_address[16];
	__u16 destination_port;
	__u16 address_family;
	__u8 protocol;
	__u8 reserved[3];
};

struct agentshield_event {
	__u16 schema_version;
	__u16 event_type;
	__u16 action;
	__u16 action_result;

	__u64 timestamp_ns;
	__u64 cgroup_id;

	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;

	__u32 profile_id;
	__u32 policy_id;
	__u32 rule_id;
	__u32 flags;
	__u32 syscall_flags;
	/* Exec events store captured argc + 1; non-exec events store 0. */
	__u32 captured_argc_plus_one;

	char comm[AGENTSHIELD_COMM_LEN];
	char data[AGENTSHIELD_DATA_LEN];
};

_Static_assert(sizeof(struct agentshield_event) == 336,
	       "agentshield_event ABI size changed");
_Static_assert(__builtin_offsetof(struct agentshield_event,
				 captured_argc_plus_one) == 60,
	       "agentshield_event argc offset changed");
_Static_assert(__builtin_offsetof(struct agentshield_event, data) == 80,
	       "agentshield_event data offset changed");
_Static_assert(sizeof(struct agentshield_network_payload) == 24,
	       "agentshield_network_payload ABI size changed");

#endif // AGENTSHIELD_EVENTS_H
