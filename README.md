# sbx

A simple CLI tool for managing EC2 sandbox instances. Automatically provisions infrastructure and handles instance lifecycle.

## Features

- Auto-creates VPC, subnet, security group, and SSH key pair
- Resolves AMI aliases (e.g., `debian-13`, `ubuntu-24.04`)
- Stops instances on SSH disconnect (cost savings)
- SSH tunneling for local development

## Installation

```bash
bun install
bun link sbx # Makes `sbx` available globally
```

> Note: Make sure you have `export PATH="$HOME/.bun/bin:$PATH"` in your shell profile.

## Quick Start

```bash
# Initialize config
sbx init

# Edit ~/.config/sbx/config.json with your settings
# Then connect to an instance (creates if needed)
sbx mybox
```

## Configuration

Config lives at `~/.config/sbx/config.json`:

```json
{
  "region": "us-west-1",
  "instanceType": "c8g.2xlarge",
  "amiId": "debian-13",
  "sshUser": "admin",
  "volumeSize": 20,
  "aws": {
    "accessKeyId": "...",
    "secretAccessKey": "..."
  }
}
```

### Options

| Field | Description |
|-------|-------------|
| `region` | AWS region |
| `instanceType` | EC2 instance type |
| `amiId` | AMI ID or alias |
| `sshUser` | SSH username (depends on AMI) |
| `volumeSize` | Root volume size in GB (default: 8) |
| `useSpot` | Use spot instances for cost savings |
| `aws.accessKeyId` | AWS access key (optional if using profile) |
| `aws.secretAccessKey` | AWS secret key |
| `aws.profile` | AWS profile name (alternative to keys) |

### AMI Aliases

**ARM64 (Graviton):**

| Alias | SSH User |
|-------|----------|
| `debian-12`, `debian-13` | `admin` |
| `ubuntu-22.04`, `ubuntu-24.04` | `ubuntu` |
| `al2023`, `amazon-linux-2` | `ec2-user` |

**x86_64 (AMD/Intel):**

| Alias | SSH User |
|-------|----------|
| `debian-12-amd64`, `debian-13-amd64` | `admin` |
| `ubuntu-22.04-amd64`, `ubuntu-24.04-amd64` | `ubuntu` |
| `al2023-amd64`, `amazon-linux-2-amd64` | `ec2-user` |

Or use a direct AMI ID: `ami-xxxxxxxxx`

### Spot Instances (`useSpot`)

Set `useSpot: true` in your config to request a spot instance instead of on-demand. sbx creates a persistent spot request and uses the `stop` interruption behavior, which means AWS can reclaim capacity at any time and your instance may stop. When that happens, just run `sbx <name>` again to start it back up when capacity is available.

On `sbx delete <name>` (or `sbx destroy`), sbx will also cancel any associated spot request to avoid it re-fulfilling later.

## Usage

```bash
# Connect to instance (creates if it doesn't exist)
sbx <name>

# List instances
sbx list
sbx ls

# Delete instance
sbx delete <name>
sbx rm <name>

# SSH tunnel (forwards local port to remote)
sbx tunnel <name> <local-port>:<remote-port>
sbx proxy <name> 3000:3000

# Resize volume (instance must be stopped)
sbx resize <name> <size-gb>

# Destroy all sbx resources (instances, VPC, etc.)
sbx destroy
```

## Auto-provisioned Resources

On first use, sbx creates (tagged `sbx-managed`):

- VPC (`10.0.0.0/16`)
- Internet Gateway
- Subnet (`10.0.1.0/24`)
- Security Group (SSH access)
- SSH Key Pair (stored at `~/.config/sbx/keys/`)

These are reused for all instances in the region.

## License

MIT
