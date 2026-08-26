"use client";

import { useRouter } from "next/navigation";
import { useTransition } from "react";

export function RefreshPolicies() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  return (
    <button disabled={pending} onClick={() => startTransition(() => router.refresh())} type="button">
      {pending ? "Refreshing…" : "Refresh view"}
    </button>
  );
}
