export const metrics = [
  { label: "Active runs", value: "02" },
  { label: "Kernel events", value: "1,284" },
  { label: "Policy hits", value: "17" },
  { label: "Blocked", value: "04" },
];

export const recentEvents = [
  {
    time: "12:16:03.421",
    run: "demo-python-agent",
    event: "FILE_OPEN",
    subject: "/etc/passwd",
    severity: "high",
    result: "alert",
  },
  {
    time: "12:16:04.108",
    run: "demo-python-agent",
    event: "EXEC_ATTEMPT",
    subject: "/bin/sh -c curl",
    severity: "medium",
    result: "audit",
  },
  {
    time: "12:16:04.812",
    run: "research-agent",
    event: "NET_CONNECT",
    subject: "203.0.113.10:443",
    severity: "high",
    result: "blocked",
  },
];

export const policies = [
  { name: "Sensitive file access", scope: "sandbox", mode: "alert", status: "enabled" },
  { name: "Network egress default deny", scope: "sandbox", mode: "block", status: "enabled" },
  { name: "Destructive shell commands", scope: "sandbox", mode: "kill", status: "draft" },
];

export const diagnostics = [
  { name: "Linux kernel", status: "pending", detail: "Waiting for control-plane diagnostics" },
  { name: "BTF", status: "pending", detail: "/sys/kernel/btf/vmlinux" },
  { name: "cgroup v2", status: "pending", detail: "/sys/fs/cgroup" },
  { name: "BPF loader", status: "pending", detail: "cilium/ebpf integration planned" },
];
