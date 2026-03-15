# Rules and Versioning

Rule updates are versioned with a monotonically increasing epoch.

- `rules_epoch` map keeps current epoch value.
- Any mutation to rule maps increments the epoch.
- Control plane can poll `/rules/epoch` to detect changes.

Map pinning:
- Start loader with `--pin-maps /sys/fs/bpf/pazuzu` to persist maps in bpffs.
- This allows reloading programs while keeping rule state.
