# BoxForge

BoxForge is an educational Linux container runtime written in C11. It uses Linux namespaces, cgroup v2 resource limits, capability dropping, seccomp, and a custom root filesystem.

## Features

- User, PID, UTS, mount, and network namespaces
- Root filesystem isolation using `pivot_root`
- Private `/proc` mount
- Memory, CPU, and PID limits through cgroup v2
- Capability dropping and seccomp filtering
- PID 1 supervision, signal forwarding, and exit-code propagation
- Cgroup cleanup after normal workload termination

## Requirements

- Linux with namespace support
- GCC and Make
- cgroup v2 with the required controllers enabled
- A root filesystem containing the requested executable
- Appropriate permissions for namespace and cgroup operations

## Build

```sh
make clean
make
```

## Run

```sh
./boxforge help
./boxforge run "$HOME/BoxForge/rootfs" /bin/sh
```

For resource limits on the tested WSL2 setup, use a delegated systemd scope:

```sh
systemd-run --user --scope -p Delegate=yes -- \
  ./boxforge run \
  --memory 128M --cpu 50% --pids 64 \
  "$HOME/BoxForge/rootfs" /bin/sh
```

## Validation

Development tests covered compilation, CLI help, namespace and hostname checks, root filesystem inspection, capability and seccomp status, cgroup resource limits, exit-code propagation, signal termination, and normal-exit cleanup.

## Security limitations

BoxForge is an educational project, not a production-hardened container engine. Its seccomp policy is a targeted denylist rather than a comprehensive syscall allowlist. Do not use it to run untrusted workloads on security-sensitive systems.

## License

Add the project's chosen license and retain any required third-party notices.
