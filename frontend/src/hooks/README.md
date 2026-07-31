# hooks/ — React Query hooks

TanStack Query hooks that own server state: `useStartAudit`, `useAuditStatus`, `useReport`, and an
SSE subscription hook for the progress stream. Components consume these; they never call `api/` directly.
