# OCI Runtime Specification Implementation

This container runtime now supports the **Open Container Initiative (OCI) Runtime Specification v1.0.2**, making it fully compatible with standard container tools and orchestrators.

## OCI Compliance Features

### 1. **Standard OCI Commands**

The runtime supports all required OCI runtime commands:

- `create` - Create a container from a bundle
- `start` - Start a created container  
- `kill` - Send signals to a container
- `delete` - Delete a stopped container
- `state` - Query container state
- `list` - List all containers (extension)
- `run` - Create and start in one operation (extension)
- `spec` - Generate OCI spec template (extension)

### 2. **OCI Bundle Support**

- Reads standard `config.json` from bundle directory
- Supports `rootfs/` directory structure
- Validates OCI spec compliance
- Converts OCI spec to internal configuration

### 3. **OCI State Management**

- Maintains container state per OCI specification
- States: `creating`, `created`, `running`, `stopped`
- JSON state output compatible with OCI tools
- Persistent state storage in `/run/oci-runtime/`

### 4. **OCI Process Configuration**

- Process arguments and environment
- Working directory and user settings
- Capabilities management
- Resource limits (rlimits)
- No new privileges flag

### 5. **OCI Filesystem Support**

- Root filesystem configuration
- Mount point specifications
- Read-only root support
- Standard system mounts (/proc, /sys, /dev, etc.)

### 6. **OCI Linux Features**

- Linux namespaces (PID, Network, IPC, UTS, Mount, User)
- Cgroup resource limits (memory, CPU, PIDs)
- Seccomp security profiles
- UID/GID mappings for rootless mode

### 7. **OCI Hooks**

- Prestart, poststart, and poststop hooks
- Hook timeout and environment configuration
- Compatible with existing OCI hook tools

## Usage Examples

### Generate OCI Spec Template
```bash
./gophertainer spec --output config.json
```

### Create Container Bundle
```bash
mkdir mycontainer
cd mycontainer
../gophertainer spec
mkdir rootfs
# Add your rootfs content to rootfs/
```

### Create and Run Container
```bash
# Create container
./gophertainer create --bundle ./mycontainer my-container-id

# Start container
./gophertainer start my-container-id

# Or create and start in one command
./gophertainer run --bundle ./mycontainer my-container-id
```

### Container Management
```bash
# List containers
./gophertainer list

# Get container state
./gophertainer state my-container-id

# Kill container
./gophertainer kill --signal TERM my-container-id

# Delete container
./gophertainer delete my-container-id
```

### Advanced Options
```bash
# Run with PID file
./gophertainer run --pid-file /var/run/container.pid --detach my-container

# Force delete running container
./gophertainer delete --force my-container

# Custom bundle path
./gophertainer create --bundle /path/to/bundle container-id
```

## OCI Spec Template

The generated OCI spec includes:

```json
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": true,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh"],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
      "effective": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
      "inheritable": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
      "permitted": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"]
    },
    "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
    "noNewPrivileges": true
  },
  "root": {"path": "rootfs", "readonly": false},
  "hostname": "container",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
    {"destination": "/sys", "type": "sysfs", "source": "sysfs"}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"}, {"type": "network"}, {"type": "ipc"},
      {"type": "uts"}, {"type": "mount"}
    ],
    "resources": {
      "memory": {"limit": 268435456},
      "cpu": {"shares": 1024}
    }
  }
}
```

## Compatibility

This implementation is compatible with:

- **containerd** - Can be used as a runtime via containerd
- **CRI-O** - Compatible as an OCI runtime
- **Podman** - Can be configured as an alternative runtime
- **Docker** - Can be used via containerd integration
- **Kubernetes** - Works through CRI-O or containerd

## Configuration

To use with containerd, add to `/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.gophertainer]
  runtime_type = "io.containerd.runc.v2"
  runtime_engine = "/path/to/gophertainer"
```

For CRI-O, add to `/etc/crio/crio.conf`:

```toml
[crio.runtime.runtimes.gophertainer]
runtime_path = "/path/to/gophertainer"
runtime_type = "oci"
```

## Security Features

- **Seccomp filtering** - Restricts system calls
- **Capability dropping** - Removes unnecessary privileges  
- **No new privileges** - Prevents privilege escalation
- **Namespace isolation** - Process, network, filesystem isolation
- **Resource limits** - Memory, CPU, and PID limits
- **Read-only root** - Immutable container filesystem
- **Rootless mode** - Run without root privileges

## Standards Compliance

This implementation follows:

- **OCI Runtime Specification v1.0.2**
- **OCI Image Format Specification**
- **Linux Container Standards**
- **POSIX Compliance**
- **LSB (Linux Standard Base)**

## Development

The OCI implementation is modular and extensible:

- `oci.go` - Core OCI runtime logic
- `oci_cli.go` - Command-line interface
- `config.go` - Configuration management
- `container.go` - Container lifecycle
- `utils.go` - Utility functions

Add new OCI features by extending these modules while maintaining backward compatibility with the existing runtime interface.