Gophertainer (Beta)
A container runtime built with Go, fully compatible with the Open Container Initiative (OCI) specification.

Gophertainer is a container runtime that fully adheres to the OCI Runtime Specification v1.0.2. It offers advanced security features, checkpoint/restore capabilities, and a flexible plugin system.

> ⚠️ Beta Release: This is a feature-complete beta version still undergoing final testing. Please report any issues. It’s not yet recommended for production use.



🚀 Core Features

OCI Compliant: Fully implements the OCI Runtime Specification v1.0.2.

Dual Operation: Supports both standalone mode and OCI-compliant command interface.

Security: Advanced hardening with features like namespace isolation (PID, Net, IPC, etc.), Seccomp filtering, rootless mode, and no_new_privs.

Checkpoint/Restore: Provides full container state checkpointing and restoration via CRIU, enabling live migration.

Networking: Supports standard bridge networking and CNI plugins for more complex network setups.

Resource Management: Manages CPU, memory, and process limits using both cgroup v1 and v2.

Extensible: A secure, event-driven plugin system that allows for extending functionalities (Storage, Network, Monitoring).


📋 Prerequisites

Go 1.23+

Linux Kernel 4.14+

CRIU (optional, for checkpoint/restore)

CNI Plugins (optional, for CNI networking)


🛠️ Installation

1. Clone the repository:

git clone https://github.com/xodudrkd/gophertainer
cd Golang


2. Build the binary:

go build -o gophertainer .


3. Optionally, install it to your system path:

sudo mv gophertainer /usr/local/bin/



🚦 Quick Start

Display help

gophertainer --help

Standalone Mode

Run an interactive Alpine Linux container:

sudo gophertainer --name alpine-test --rootfs /path/to/alpine.tar.gz --cmd "/bin/sh" -i -t

OCI Mode

Create and run a container from an OCI bundle:

1. Create an OCI bundle spec:

mkdir my-container && cd my-container
gophertainer spec


2. Add your rootfs to the 'rootfs' directory.


3. Create and run the container:

sudo gophertainer create my-container-id --bundle .
sudo gophertainer start my-container-id



📖 Basic Usage

Gophertainer follows standard OCI lifecycle commands.

Generate an OCI spec file:

gophertainer spec

Create a container from a bundle:

gophertainer create <container-id> --bundle <path>

Start the container:

gophertainer start <container-id>

List running containers:

gophertainer list

Get container state:

gophertainer state <container-id>

Send a signal to the container (e.g., SIGTERM):

gophertainer kill <container-id> TERM

Delete the container:

gophertainer delete <container-id>


Checkpoint & Restore

Create a checkpoint of a running container:

sudo gophertainer checkpoint my-running-container

Restore a container from a checkpoint:

sudo gophertainer restore <checkpoint-id>


🤝 Contributing

We encourage contributions! Here’s how you can get involved:

1. Fork the repository.


2. Create a feature branch:

git checkout -b feature/my-new-feature


3. Commit your changes:

git commit -m 'Add some feature'


4. Push the branch:

git push origin feature/my-new-feature


5. Open a Pull Request.



📄 License

Refer to the LICENSE file for more details.