# Gophertainer (Beta)

**A container runtime written in Go - Beta Version**

Gophertainer is a comprehensive container runtime implementation that provides full compatibility with the Open Container Initiative (OCI) Runtime Specification v1.0.2, while offering advanced security features, checkpoint/restore capabilities, and flexible deployment options.

> **⚠️ Beta Release**: This is a beta version of Gophertainer. While feature-complete, it is still undergoing testing and refinement. Do NOT Use in production environments yet. Meny command can fail just report error in issues tab.

## 🚀 Features

### Core Runtime
- **OCI Compliance**: Full OCI Runtime Specification v1.0.2 implementation
- **Dual Mode Operation**: Both standalone and OCI-compliant command interfaces
- **Container Lifecycle**: Complete create, start, stop, delete workflow
- **State Management**: Persistent container state tracking

### Security & Isolation
- **Advanced Security Hardening**: Multi-layered security protections
- **Namespace Isolation**: PID, Network, IPC, UTS, Mount, and User namespaces
- **Capabilities Management**: Fine-grained Linux capability control
- **Seccomp Filtering**: System call filtering with custom profiles
- **Rootless Mode**: Run containers without root privileges
- **No New Privileges**: Prevents privilege escalation attacks

### Checkpoint & Restore
- **CRIU Integration**: Advanced checkpoint/restore using CRIU
- **State Persistence**: Save and restore complete container state
- **Live Migration**: Move running containers between hosts
- **Pre-dump Support**: Minimize downtime with iterative checkpointing

### Networking
- **Bridge Networking**: Traditional Linux bridge networking
- **CNI Support**: Modern Container Network Interface plugins
- **IPv4/IPv6 Dual Stack**: Full IPv6 support alongside IPv4
- **Network Isolation**: Complete network namespace separation

### Storage & Filesystem
- **Multiple Storage Drivers**: Support for various storage backends
- **Volume Management**: Flexible host-container volume mounting
- **Rootfs Formats**: Support for directories, tar archives, and disk images
- **Loop Device Management**: Automated loop device handling for disk images

### Resource Management
- **Cgroup v1/v2**: Full support for both cgroup versions
- **CPU Limits**: CPU shares and quota management
- **Memory Limits**: Memory usage constraints and OOM protection
- **Process Limits**: PID namespace process counting
- **I/O Controls**: Disk I/O throttling and prioritization

### Monitoring & Recovery
- **Built-in Monitoring**: Container health monitoring
- **Automatic Recovery**: Container restart on failure
- **Metrics Collection**: Resource usage and performance metrics
- **Graceful Shutdown**: Clean container termination handling

### Plugin Architecture
- **Extensible Plugin System**: Support for third-party extensions
- **Multiple Plugin Types**: Storage, Network, Monitoring, Runtime, and Security plugins
- **Event-Driven Architecture**: Rich event system for plugin communication
- **Security Framework**: Plugin validation, integrity checking, and sandboxing
- **Hot-Pluggable**: Dynamic plugin loading/unloading without runtime restart
- **Configuration Management**: Schema-based plugin configuration with validation

## 📋 Prerequisites

### Required Tools
- **Go 1.23+**: For building from source
- **Linux Kernel 4.14+**: Container namespace support
- **Root Access**: For full functionality (or user namespace support for rootless)

### Optional Dependencies
- **CRIU**: For checkpoint/restore functionality
- **CNI Plugins**: For advanced networking
- **systemd**: For cgroup v2 delegation (rootless mode)

## 🛠️ Installation

### Build from Source

```bash
# Clone the repository
git clone <repository-url>
cd Golang

# Build the binary
go build -o gophertainer .

# Install to system path (optional)
sudo mv gophertainer /usr/local/bin/
```

### Dependencies
```bash
# Install required Go modules
go mod tidy

# Install optional CRIU (for checkpoint/restore)
# Ubuntu/Debian:
sudo apt-get install criu

# RHEL/CentOS/Fedora:
sudo dnf install criu
```

## 🚦 Quick Start

### Standalone Mode

```bash
# Run an interactive Alpine Linux container
sudo gophertainer --name alpine-test --rootfs /path/to/alpine.tar.gz --cmd "/bin/sh" -i -t

# Run a detached container with resource limits
sudo gophertainer --name web-server \
    --rootfs /path/to/nginx.tar.gz \
    --cmd "nginx -g 'daemon off;'" \
    --mem 512 --cpu 1.0 \
    --volume /var/www:/usr/share/nginx/html \
    --detach
```

### OCI Mode

```bash
# Create an OCI bundle
mkdir my-container
cd my-container
gophertainer spec

# Add your rootfs
mkdir rootfs
# ... populate rootfs with your container filesystem

# Create and run the container
sudo gophertainer create my-container-id --bundle .
sudo gophertainer start my-container-id

# Manage the container
sudo gophertainer state my-container-id
sudo gophertainer kill my-container-id TERM
sudo gophertainer delete my-container-id
```

### Checkpoint & Restore

```bash
# Create a checkpoint
sudo gophertainer checkpoint my-running-container

# List available checkpoints
sudo gophertainer checkpoint-list

# Restore from checkpoint
sudo gophertainer restore <checkpoint-id>
```

## 📖 Usage

### Command-Line Options

#### Standalone Mode
```bash
gophertainer [OPTIONS]
```

**Core Options:**
- `--name <string>`: Container name (required)
- `--rootfs <path>`: Root filesystem path (required)
- `--cmd "<command>"`: Command to execute (required unless -i)
- `-i, --interactive`: Run interactive shell
- `-t, --tty`: Allocate pseudo-TTY

**Resource Limits:**
- `--mem <MB>`: Memory limit in megabytes
- `--cpu <float>`: CPU limit (e.g., 0.5 for 50%, 2.0 for 2 cores)
- `--pids <int>`: Process limit

**Security:**
- `--rootless`: Enable rootless mode
- `--no-new-privs`: Set no_new_privs bit
- `--seccomp <profile>`: Seccomp profile path

**Networking:**
- `--net <CIDR>`: IPv4 network CIDR
- `--net6 <CIDR>`: IPv6 network CIDR
- `--cni`: Enable CNI networking
- `--bridge <name>`: Bridge name

### OCI Commands

#### Container Lifecycle
```bash
# Generate OCI spec template
gophertainer spec [--output config.json]

# Create container
gophertainer create <id> --bundle <path>

# Start container
gophertainer start <id>

# Get container state
gophertainer state <id>

# Send signal to container
gophertainer kill <id> [SIGNAL]

# Delete container
gophertainer delete <id> [--force]

# List containers
gophertainer list [--format table|json]
```

#### Checkpoint Operations
```bash
# Create checkpoint
gophertainer checkpoint <container-name> [--leave-running]

# Restore from checkpoint
gophertainer restore <checkpoint-id> [--detach]

# List checkpoints
gophertainer checkpoint-list

# Delete checkpoint
gophertainer checkpoint-delete <checkpoint-id>
```

## 🏗️ Architecture

### Core Components

```
main.go              - Entry point and process management
container.go         - Container lifecycle management
config.go           - Configuration structures
oci.go              - OCI specification implementation
oci_cli.go          - OCI command-line interface
```

### Security & Hardening
```
security_hardening.go - Advanced security protections
validation.go        - Input validation and sanitization
errors.go           - Error handling and reporting
```

### Resource Management
```
memory_pool.go       - Memory management and pooling
resource_manager.go  - Resource allocation and limits
cni.go              - Container Network Interface support
```

### Storage & I/O
```
storage_drivers.go   - Storage backend implementations
cleanup.go          - Resource cleanup management
utils.go            - Utility functions
```

### Advanced Features
```
checkpoint.go        - CRIU-based checkpoint/restore
runtime_hooks.go     - Container lifecycle hooks
monitoring_recovery.go - Health monitoring and recovery
dependency_injection.go - Clean architecture DI
metrics.go          - Performance metrics collection
signals.go          - Signal handling
```

### Plugin System
```
plugin.go           - Core plugin interface and lifecycle management
plugin_registry.go  - Plugin discovery and registry management
plugin_events.go    - Event system for plugin communication
plugin_security.go  - Plugin security validation and sandboxing
plugin_integration.go - Container runtime integration layer
example_plugins.go  - Example plugin implementations
```

### Testing
```
test.go                    - Basic functionality tests
enhanced_container_test.go - Advanced container testing
```

## 🔧 Configuration

### Environment Variables
- `DEBUG=1`: Enable debug logging
- `GOPHERTAINER_ROOT`: Override default state directory
- `CRIU_PATH`: Path to CRIU binary (if not in PATH)

### Config Files
- **OCI Bundle**: `config.json` (OCI specification)
- **Checkpoint State**: Stored in `/var/lib/gophertainer/checkpoints/`
- **Runtime State**: Stored in `/run/oci-runtime/`
- **Plugin Configuration**: `/etc/gophertainer/plugin-config/`
- **Plugin Directories**: `/usr/local/lib/gophertainer/plugins/`, `/etc/gophertainer/plugins/`

### Rootless Setup
```bash
# Configure user namespace mappings
echo "user:100000:65536" | sudo tee -a /etc/subuid
echo "user:100000:65536" | sudo tee -a /etc/subgid

# Enable cgroup v2 delegation (systemd systems)
sudo systemctl enable --now systemd-oomd
systemctl --user enable --now systemd-oomd.service
```

## 🔌 Plugin System

### Overview

Gophertainer features a comprehensive plugin architecture that allows third-party developers to extend container functionality without modifying the core runtime. The plugin system is designed with security, performance, and ease of development in mind.

### Plugin Types

#### Storage Plugins
Extend storage capabilities with custom backends, compression, encryption, or distributed storage systems.

```go
type StoragePlugin interface {
    Plugin
    Mount(source, target string, options map[string]interface{}) error
    Unmount(target string) error
    CreateSnapshot(source, snapshot string) error
}
```

#### Network Plugins
Implement custom networking solutions, SDN integration, or specialized network configurations.

```go
type NetworkPlugin interface {
    Plugin
    PluginEventHandler
    SetupNetwork(containerID, netNS string) (*NetworkResult, error)
    TeardownNetwork(containerID, netNS string) error
}
```

#### Monitoring Plugins
Add custom metrics collection, alerting, or integration with monitoring systems.

```go
type MonitoringPlugin interface {
    Plugin
    PluginEventHandler
    CollectMetrics() map[string]interface{}
    GetHealthStatus() HealthStatus
}
```

### Plugin Development

#### Basic Plugin Structure
```go
package main

import (
    "context"
    "fmt"
)

type MyPlugin struct {
    config map[string]interface{}
    logger *slog.Logger
}

func NewMyPlugin() Plugin {
    return &MyPlugin{
        logger: slog.Default().With("plugin", "my-plugin"),
    }
}

func (p *MyPlugin) GetInfo() PluginInfo {
    return PluginInfo{
        Name:        "my-plugin",
        Version:     "1.0.0",
        Type:        PluginTypeStorage,
        Description: "Example plugin implementation",
        Author:      "Your Name",
        Config: PluginConfigSchema{
            Properties: map[string]PluginConfigProperty{
                "storage_path": {
                    Type:        "string",
                    Default:     "/var/lib/my-plugin",
                    Description: "Storage path for plugin data",
                },
            },
            Required: []string{"storage_path"},
        },
    }
}

func (p *MyPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
    p.config = config
    // Plugin initialization logic
    return nil
}

func (p *MyPlugin) Start(ctx context.Context) error {
    // Start plugin services
    return nil
}

func (p *MyPlugin) Stop(ctx context.Context) error {
    // Stop plugin services
    return nil
}

func (p *MyPlugin) Cleanup(ctx context.Context) error {
    // Cleanup plugin resources
    return nil
}

// Export the plugin constructor
func NewPlugin() Plugin {
    return NewMyPlugin()
}
```

#### Building Plugins
```bash
# Build as shared library
go build -buildmode=plugin -o my-plugin.so my-plugin.go

# Install to plugin directory
sudo mv my-plugin.so /usr/local/lib/gophertainer/plugins/
```

#### Plugin Configuration
Create a JSON configuration file:
```json
{
  "name": "my-plugin",
  "enabled": true,
  "storage_path": "/var/lib/my-plugin",
  "custom_option": "value"
}
```

Save to `/etc/gophertainer/plugin-config/my-plugin.json`

### Plugin Management

#### Discovery and Loading
```bash
# List available plugins
gophertainer plugin list

# Load specific plugin
gophertainer plugin load my-plugin

# Show plugin info
gophertainer plugin info my-plugin

# Unload plugin
gophertainer plugin unload my-plugin
```

#### Plugin Security
- **Binary Validation**: SHA256 hash verification
- **Path Restrictions**: Allowed directory enforcement
- **Permission Checks**: File permission validation
- **Signature Verification**: Digital signature support (configurable)
- **Sandboxed Execution**: Isolated plugin execution environment

#### Event System
Plugins can subscribe to container lifecycle events:

```go
func (p *MyPlugin) HandleEvent(ctx context.Context, event *PluginEvent) error {
    switch event.Type {
    case ContainerEventStarting:
        // Handle container start
    case StorageEventMounting:
        // Handle storage mount
    case NetworkEventSetup:
        // Handle network setup
    }
    return nil
}

func (p *MyPlugin) GetHandledEvents() []PluginEventType {
    return []PluginEventType{
        ContainerEventStarting,
        StorageEventMounting,
        NetworkEventSetup,
    }
}
```

### Example Plugins

The repository includes several example plugins demonstrating different capabilities:

#### Storage Plugin Example
- Background storage maintenance
- Compression and deduplication
- Snapshot management
- Configurable storage paths

#### Network Plugin Example
- Custom bridge creation
- VLAN tagging support
- Network monitoring
- Event-driven network management

#### Monitoring Plugin Example
- Metrics collection and export
- Resource usage tracking
- Alert generation
- Dashboard integration

### Plugin Configuration

#### Global Plugin Settings
```bash
# Enable plugin system
export GOPHERTAINER_PLUGINS_ENABLED=true

# Set plugin directories
export GOPHERTAINER_PLUGIN_DIRS="/usr/local/lib/gophertainer/plugins:/opt/plugins"

# Enable plugin security
export GOPHERTAINER_PLUGIN_SECURITY=true
```

#### Runtime Configuration
Plugins are automatically discovered and loaded during runtime initialization. Configuration is loaded from:
1. `/etc/gophertainer/plugin-config/` (system-wide)
2. `~/.config/gophertainer/plugin-config/` (user-specific)
3. Environment variables
4. Command-line flags

## 🔌 Integration

### Container Orchestrators

#### containerd
Add to `/etc/containerd/config.toml`:
```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.gophertainer]
  runtime_type = "io.containerd.runc.v2"
  runtime_engine = "/usr/local/bin/gophertainer"
```

#### CRI-O
Add to `/etc/crio/crio.conf`:
```toml
[crio.runtime.runtimes.gophertainer]
runtime_path = "/usr/local/bin/gophertainer"
runtime_type = "oci"
```

#### Kubernetes
Use with CRI-O or containerd runtime classes:
```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gophertainer
handler: gophertainer
```

## 📊 Monitoring

### Built-in Metrics
- Container count and lifecycle events
- Resource usage (CPU, memory, I/O)
- Security events and violations
- Network traffic statistics
- Checkpoint/restore performance

### Health Checks
- Container process monitoring
- Resource exhaustion detection
- Automatic container restart
- Graceful shutdown handling

## 🛡️ Security

### Security Features
- **Defense in Depth**: Multiple security layers
- **Secure Defaults**: Conservative default configuration
- **Input Validation**: Comprehensive input sanitization
- **Resource Limits**: Prevent resource exhaustion attacks
- **Audit Logging**: Security event logging

### Security Hardening
- Process limit enforcement
- Memory exhaustion protection
- File descriptor limits
- Disk space monitoring
- Network resource limiting
- Path traversal prevention
- Anti-exploit protections

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied Errors
```bash
# Solution 1: Run as root
sudo gophertainer ...

# Solution 2: Use rootless mode
gophertainer --rootless ...
```

#### Network Setup Failures
```bash
# Ensure bridge-utils is installed
sudo apt-get install bridge-utils

# Check network namespaces
sudo ip netns list
```

#### Checkpoint/Restore Issues
```bash
# Verify CRIU installation
criu check

# Check CRIU logs
sudo criu dump --help
```

### Debug Mode
```bash
# Enable debug logging
DEBUG=1 gophertainer ...

# Check container state
gophertainer state <container-id>
```

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup
```bash
# Install development dependencies
go mod download

# Run tests
go test ./...

# Build development version
go build -tags dev -o gophertainer .
```

## 📄 License
see the [LICENSE](LICENSE) file for details.
## 📚 References

- [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec)
- [Container Network Interface (CNI)](https://github.com/containernetworking/cni)
- [CRIU Documentation](https://criu.org/Documentation)
- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Control Groups](https://www.kernel.org/doc/Documentation/cgroup-v2.txt)

---

**Gophertainer** - *Secure, Fast, and Reliable Container Runtime*