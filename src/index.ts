#!/usr/bin/env bun
import {
  EC2Client,
  DescribeInstancesCommand,
  DescribeImagesCommand,
  DescribeVpcsCommand,
  DescribeSubnetsCommand,
  DescribeSecurityGroupsCommand,
  DescribeKeyPairsCommand,
  DescribeInternetGatewaysCommand,
  DescribeRouteTablesCommand,
  CreateVpcCommand,
  CreateSubnetCommand,
  CreateSecurityGroupCommand,
  CreateKeyPairCommand,
  CreateInternetGatewayCommand,
  CreateRouteCommand,
  AttachInternetGatewayCommand,
  AuthorizeSecurityGroupIngressCommand,
  ModifyVpcAttributeCommand,
  RunInstancesCommand,
  StartInstancesCommand,
  StopInstancesCommand,
  TerminateInstancesCommand,
  DeleteVpcCommand,
  DeleteSubnetCommand,
  DeleteSecurityGroupCommand,
  DeleteKeyPairCommand,
  DeleteInternetGatewayCommand,
  DetachInternetGatewayCommand,
  DescribeVolumesCommand,
  ModifyVolumeCommand,
  DescribeVolumesModificationsCommand,
  waitUntilInstanceRunning,
  waitUntilInstanceStopped,
  waitUntilInstanceTerminated,
  type Instance,
} from "@aws-sdk/client-ec2";
import { mkdir, readFile, writeFile, chmod, unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const CONFIG_DIR = path.join(os.homedir(), ".config", "sbx");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");
const KEYS_DIR = path.join(CONFIG_DIR, "keys");
const SBX_TAG = "sbx-managed";

import { SbxConfigSchema, type SbxConfig } from "./schema";

const DEFAULT_CONFIG: SbxConfig = {
  region: "us-east-1",
  instanceType: "t4g.micro",
  amiId: "debian-12",
  sshUser: "admin",
  volumeSize: 8,
  aws: {
    profile: "default",
  },
};

// AMI alias patterns for different distros
const AMI_PATTERNS: Record<string, { owner: string; pattern: string }> = {
  "debian-12": { owner: "136693071363", pattern: "debian-12-arm64-*" },
  "debian-13": { owner: "136693071363", pattern: "debian-13-arm64-*" },
  "ubuntu-22.04": { owner: "099720109477", pattern: "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*" },
  "ubuntu-24.04": { owner: "099720109477", pattern: "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*" },
  "al2023": { owner: "137112412989", pattern: "al2023-ami-2023*-arm64" },
  "amazon-linux-2": { owner: "137112412989", pattern: "amzn2-ami-hvm-*-arm64-gp2" },

  "debian-12-amd64": { owner: "136693071363", pattern: "debian-12-amd64-*" },
  "debian-13-amd64": { owner: "136693071363", pattern: "debian-13-amd64-*" },
  "ubuntu-22.04-amd64": { owner: "099720109477", pattern: "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" },
  "ubuntu-24.04-amd64": { owner: "099720109477", pattern: "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" },
  "al2023-amd64": { owner: "137112412989", pattern: "al2023-ami-2023*-x86_64" },
  "amazon-linux-2-amd64": { owner: "137112412989", pattern: "amzn2-ami-hvm-*-x86_64-gp2" },
};

const HELP_TEXT = `sbx - EC2 sandbox helper

Usage:
  sbx init                                      Initialize config
  sbx list|ls                                   List instances  
  sbx delete|rm <instance-name>                 Terminate instance
  sbx resize <instance-name> <size-gb>          Resize volume (instance must be stopped)
  sbx tunnel|proxy <instance-name> <local>:<remote>   SSH tunnel
  sbx destroy                                   Delete all sbx resources
  sbx <instance-name>                           Connect (creates if needed)
`;

function log(msg: string): void {
  console.log(`[sbx] ${msg}`);
}

async function loadConfig(): Promise<SbxConfig> {
  const raw = await readFile(CONFIG_PATH, "utf8");
  const parsed = SbxConfigSchema.safeParse(JSON.parse(raw));
  if (!parsed.success) {
    throw new Error(`Invalid config: ${parsed.error.errors.map(e => e.message).join(", ")}`);
  }
  return parsed.data;
}

async function writeDefaultConfig(): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });
  await writeFile(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2));
}

function getEc2Client(config: SbxConfig): EC2Client {
  if (config.aws?.accessKeyId && config.aws?.secretAccessKey) {
    return new EC2Client({
      region: config.region,
      credentials: {
        accessKeyId: config.aws.accessKeyId,
        secretAccessKey: config.aws.secretAccessKey,
        sessionToken: config.aws.sessionToken,
      },
    });
  }

  return new EC2Client({ region: config.region });
}

// ─────────────────────────────────────────────────────────────────────────────
// AMI Resolution
// ─────────────────────────────────────────────────────────────────────────────

async function resolveAmiId(client: EC2Client, alias: string): Promise<string> {
  // If it looks like an AMI ID, return as-is
  if (alias.startsWith("ami-")) {
    return alias;
  }

  const pattern = AMI_PATTERNS[alias];
  if (!pattern) {
    throw new Error(`Unknown AMI alias: ${alias}. Use ami-xxx or one of: ${Object.keys(AMI_PATTERNS).join(", ")}`);
  }

  log(`Resolving AMI for ${alias}...`);
  const response = await client.send(
    new DescribeImagesCommand({
      Owners: [pattern.owner],
      Filters: [
        { Name: "name", Values: [pattern.pattern] },
        { Name: "state", Values: ["available"] },
      ],
    })
  );

  const images = response.Images ?? [];
  if (images.length === 0) {
    throw new Error(`No AMI found for alias: ${alias}`);
  }

  // Sort by creation date descending, pick newest
  images.sort((a, b) => (b.CreationDate ?? "").localeCompare(a.CreationDate ?? ""));
  const ami = images[0].ImageId!;
  log(`Resolved ${alias} -> ${ami}`);
  return ami;
}

// ─────────────────────────────────────────────────────────────────────────────
// Infrastructure Management (VPC, Subnet, SG, Key)
// ─────────────────────────────────────────────────────────────────────────────

async function ensureVpc(client: EC2Client): Promise<string> {
  // Check for existing sbx VPC
  const existing = await client.send(
    new DescribeVpcsCommand({
      Filters: [{ Name: "tag:Name", Values: [SBX_TAG] }],
    })
  );

  if (existing.Vpcs?.length) {
    return existing.Vpcs[0].VpcId!;
  }

  log("Creating VPC...");
  const vpc = await client.send(
    new CreateVpcCommand({
      CidrBlock: "10.0.0.0/16",
      TagSpecifications: [
        {
          ResourceType: "vpc",
          Tags: [{ Key: "Name", Value: SBX_TAG }],
        },
      ],
    })
  );

  const vpcId = vpc.Vpc!.VpcId!;

  // Enable DNS hostnames
  await client.send(
    new ModifyVpcAttributeCommand({
      VpcId: vpcId,
      EnableDnsHostnames: { Value: true },
    })
  );

  log(`Created VPC ${vpcId}`);
  return vpcId;
}

async function ensureInternetGateway(client: EC2Client, vpcId: string): Promise<string> {
  // Check for existing IGW attached to this VPC
  const existing = await client.send(
    new DescribeInternetGatewaysCommand({
      Filters: [{ Name: "attachment.vpc-id", Values: [vpcId] }],
    })
  );

  if (existing.InternetGateways?.length) {
    return existing.InternetGateways[0].InternetGatewayId!;
  }

  log("Creating Internet Gateway...");
  const igw = await client.send(
    new CreateInternetGatewayCommand({
      TagSpecifications: [
        {
          ResourceType: "internet-gateway",
          Tags: [{ Key: "Name", Value: SBX_TAG }],
        },
      ],
    })
  );

  const igwId = igw.InternetGateway!.InternetGatewayId!;

  await client.send(
    new AttachInternetGatewayCommand({
      InternetGatewayId: igwId,
      VpcId: vpcId,
    })
  );

  log(`Created and attached IGW ${igwId}`);
  return igwId;
}

async function ensureSubnet(client: EC2Client, vpcId: string, region: string): Promise<string> {
  // Check for existing sbx subnet
  const existing = await client.send(
    new DescribeSubnetsCommand({
      Filters: [
        { Name: "vpc-id", Values: [vpcId] },
        { Name: "tag:Name", Values: [SBX_TAG] },
      ],
    })
  );

  if (existing.Subnets?.length) {
    return existing.Subnets[0].SubnetId!;
  }

  log("Creating Subnet...");
  const subnet = await client.send(
    new CreateSubnetCommand({
      VpcId: vpcId,
      CidrBlock: "10.0.1.0/24",
      AvailabilityZone: `${region}a`,
      TagSpecifications: [
        {
          ResourceType: "subnet",
          Tags: [{ Key: "Name", Value: SBX_TAG }],
        },
      ],
    })
  );

  const subnetId = subnet.Subnet!.SubnetId!;
  log(`Created Subnet ${subnetId}`);
  return subnetId;
}

async function ensureRouteTable(client: EC2Client, vpcId: string, subnetId: string, igwId: string): Promise<void> {
  // Get the main route table for the VPC
  const tables = await client.send(
    new DescribeRouteTablesCommand({
      Filters: [
        { Name: "vpc-id", Values: [vpcId] },
        { Name: "association.main", Values: ["true"] },
      ],
    })
  );

  const rtId = tables.RouteTables?.[0]?.RouteTableId;
  if (!rtId) {
    throw new Error("No main route table found for VPC");
  }

  // Check if route to IGW already exists
  const routes = tables.RouteTables?.[0]?.Routes ?? [];
  const hasIgwRoute = routes.some((r) => r.GatewayId === igwId && r.DestinationCidrBlock === "0.0.0.0/0");

  if (!hasIgwRoute) {
    log("Adding route to Internet Gateway...");
    await client.send(
      new CreateRouteCommand({
        RouteTableId: rtId,
        DestinationCidrBlock: "0.0.0.0/0",
        GatewayId: igwId,
      })
    );
  }
}

async function ensureSecurityGroup(client: EC2Client, vpcId: string): Promise<string> {
  // Check for existing sbx security group
  const existing = await client.send(
    new DescribeSecurityGroupsCommand({
      Filters: [
        { Name: "vpc-id", Values: [vpcId] },
        { Name: "group-name", Values: [SBX_TAG] },
      ],
    })
  );

  if (existing.SecurityGroups?.length) {
    return existing.SecurityGroups[0].GroupId!;
  }

  log("Creating Security Group...");
  const sg = await client.send(
    new CreateSecurityGroupCommand({
      GroupName: SBX_TAG,
      Description: "sbx sandbox instances - SSH access",
      VpcId: vpcId,
      TagSpecifications: [
        {
          ResourceType: "security-group",
          Tags: [{ Key: "Name", Value: SBX_TAG }],
        },
      ],
    })
  );

  const sgId = sg.GroupId!;

  // Allow SSH from anywhere
  await client.send(
    new AuthorizeSecurityGroupIngressCommand({
      GroupId: sgId,
      IpProtocol: "tcp",
      FromPort: 22,
      ToPort: 22,
      CidrIp: "0.0.0.0/0",
    })
  );

  log(`Created Security Group ${sgId}`);
  return sgId;
}

async function ensureKeyPair(client: EC2Client, region: string): Promise<{ keyName: string; keyPath: string }> {
  const keyName = `sbx-${region}`;
  const keyPath = path.join(KEYS_DIR, `${keyName}.pem`);

  // Check if key exists in AWS
  const existing = await client.send(
    new DescribeKeyPairsCommand({
      Filters: [{ Name: "key-name", Values: [keyName] }],
    })
  );

  if (existing.KeyPairs?.length) {
    // Check if we have the local key file
    try {
      await readFile(keyPath);
      return { keyName, keyPath };
    } catch {
      throw new Error(`Key pair ${keyName} exists in AWS but local key file is missing at ${keyPath}`);
    }
  }

  log("Creating SSH Key Pair...");
  await mkdir(KEYS_DIR, { recursive: true });

  const key = await client.send(
    new CreateKeyPairCommand({
      KeyName: keyName,
      KeyType: "ed25519",
      TagSpecifications: [
        {
          ResourceType: "key-pair",
          Tags: [{ Key: "Name", Value: SBX_TAG }],
        },
      ],
    })
  );

  await writeFile(keyPath, key.KeyMaterial!);
  await chmod(keyPath, 0o600);

  log(`Created Key Pair ${keyName}, saved to ${keyPath}`);
  return { keyName, keyPath };
}

type InfraResources = {
  subnetId: string;
  securityGroupId: string;
  keyName: string;
  keyPath: string;
};

async function ensureInfrastructure(client: EC2Client, region: string): Promise<InfraResources> {
  const vpcId = await ensureVpc(client);
  const igwId = await ensureInternetGateway(client, vpcId);
  const subnetId = await ensureSubnet(client, vpcId, region);
  await ensureRouteTable(client, vpcId, subnetId, igwId);
  const securityGroupId = await ensureSecurityGroup(client, vpcId);
  const { keyName, keyPath } = await ensureKeyPair(client, region);

  return { subnetId, securityGroupId, keyName, keyPath };
}

// ─────────────────────────────────────────────────────────────────────────────
// Instance Management
// ─────────────────────────────────────────────────────────────────────────────

async function describeSbxInstances(client: EC2Client, name?: string): Promise<Instance[]> {
  const filters = [
    { Name: "tag:sbx", Values: ["true"] },
    { Name: "instance-state-name", Values: ["pending", "running", "stopping", "stopped"] },
  ];
  if (name) {
    filters.push({ Name: "tag:Name", Values: [name] });
  }

  const response = await client.send(
    new DescribeInstancesCommand({
      Filters: filters,
    })
  );

  return response.Reservations?.flatMap((reservation) => reservation.Instances ?? []) ?? [];
}

function formatInstances(instances: Instance[]): string {
  if (instances.length === 0) {
    return "No sbx instances found.";
  }

  const rows = instances.map((instance) => {
    const name = instance.Tags?.find((tag) => tag.Key === "Name")?.Value ?? "";
    return {
      name,
      id: instance.InstanceId ?? "",
      type: instance.InstanceType ?? "",
      state: instance.State?.Name ?? "",
      ip: instance.PublicIpAddress ?? instance.PrivateIpAddress ?? "-",
    };
  });

  const headers = ["Name", "InstanceId", "Type", "State", "IP"];
  const widths = headers.map((header, index) =>
    Math.max(
      header.length,
      ...rows.map((row) => [row.name, row.id, row.type, row.state, row.ip][index].length)
    )
  );

  const formatRow = (values: string[]) =>
    values
      .map((value, index) => value.padEnd(widths[index]))
      .join("  ")
      .trimEnd();

  const output = [formatRow(headers), formatRow(widths.map((width) => "-".repeat(width)))];
  rows.forEach((row) => output.push(formatRow([row.name, row.id, row.type, row.state, row.ip])));
  return output.join("\n");
}

async function ensureInstance(
  client: EC2Client,
  config: SbxConfig,
  infra: InfraResources,
  name: string
): Promise<Instance> {
  const existing = await describeSbxInstances(client, name);
  const instance = existing[0];

  if (!instance) {
    const amiId = await resolveAmiId(client, config.amiId);

    console.log(`Instance "${name}" does not exist.`);
    console.log(`  Type: ${config.instanceType}${config.useSpot ? " (spot)" : ""}`);
    console.log(`  AMI: ${config.amiId} (${amiId})`);
    console.log(`  Volume: ${config.volumeSize ?? 8}GB`);
    console.log(`  Region: ${config.region}`);

    const confirmed = await confirm("Create new instance?");
    if (!confirmed) {
      throw new Error("Aborted.");
    }

    log(`Creating instance ${name}...`);
    const created = await client.send(
      new RunInstancesCommand({
        ImageId: amiId,
        InstanceType: config.instanceType as any,
        KeyName: infra.keyName,
        MinCount: 1,
        MaxCount: 1,
        BlockDeviceMappings: [
          {
            DeviceName: "/dev/xvda",
            Ebs: {
              VolumeSize: config.volumeSize ?? 8,
              VolumeType: "gp3",
              DeleteOnTermination: true,
            },
          },
        ],
        NetworkInterfaces: [
          {
            DeviceIndex: 0,
            SubnetId: infra.subnetId,
            AssociatePublicIpAddress: true,
            Groups: [infra.securityGroupId],
          },
        ],
        InstanceMarketOptions: config.useSpot
          ? {
              MarketType: "spot",
              SpotOptions: {
                SpotInstanceType: "persistent",
                InstanceInterruptionBehavior: "stop",
              },
            }
          : undefined,
        TagSpecifications: [
          {
            ResourceType: "instance",
            Tags: [
              { Key: "Name", Value: name },
              { Key: "sbx", Value: "true" },
            ],
          },
        ],
        MetadataOptions: {
          HttpTokens: "required", // Enforce IMDSv2
          HttpEndpoint: "enabled",
        },
      })
    );

    const instanceId = created.Instances?.[0]?.InstanceId;
    if (!instanceId) {
      throw new Error("Failed to create instance.");
    }

    log(`Waiting for instance ${instanceId} to be running...`);
    await waitUntilInstanceRunning({ client, maxWaitTime: 300 }, { InstanceIds: [instanceId] });

    const [fresh] = await describeSbxInstances(client, name);
    if (!fresh) {
      throw new Error("Instance created but not found.");
    }
    return fresh;
  }

  const state = instance.State?.Name;
  const instanceId = instance.InstanceId;
  if (!instanceId) {
    throw new Error("Instance is missing an ID.");
  }

  if (state === "stopping") {
    log(`Waiting for instance to stop...`);
    await waitUntilInstanceStopped({ client, maxWaitTime: 300 }, { InstanceIds: [instanceId] });
  }

  if (state === "stopped" || state === "stopping") {
    log(`Starting instance ${name}...`);
    await client.send(new StartInstancesCommand({ InstanceIds: [instanceId] }));
  }

  if (state !== "running") {
    log(`Waiting for instance ${instanceId} to be running...`);
    await waitUntilInstanceRunning({ client, maxWaitTime: 300 }, { InstanceIds: [instanceId] });
  }

  const [fresh] = await describeSbxInstances(client, name);
  if (!fresh) {
    throw new Error("Instance not found after starting.");
  }

  return fresh;
}

function resolveHost(instance: Instance): string {
  if (instance.PublicIpAddress) {
    return instance.PublicIpAddress;
  }
  if (instance.PrivateIpAddress) {
    return instance.PrivateIpAddress;
  }
  throw new Error("No IP address available on instance.");
}

async function runSsh(command: string, args: string[]): Promise<number> {
  const proc = Bun.spawn([command, ...args], {
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  return await proc.exited;
}

async function waitForSsh(host: string, port: number, keyPath: string, user: string): Promise<void> {
  const maxAttempts = 30;
  const delayMs = 5000;

  log(`Waiting for SSH to be ready on ${host}...`);

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const proc = Bun.spawn(
        [
          "ssh",
          "-i", keyPath,
          "-o", "StrictHostKeyChecking=accept-new",
          "-o", "UserKnownHostsFile=/dev/null",
          "-o", "LogLevel=ERROR",
          "-o", "ConnectTimeout=5",
          "-o", "BatchMode=yes",
          `${user}@${host}`,
          "echo ok",
        ],
        {
          stdin: "ignore",
          stdout: "pipe",
          stderr: "pipe",
        }
      );

      const exitCode = await proc.exited;
      if (exitCode === 0) {
        log(`SSH ready after ${attempt} attempt(s)`);
        return;
      }
    } catch {
      // Connection failed, will retry
    }

    if (attempt < maxAttempts) {
      await Bun.sleep(delayMs);
    }
  }

  throw new Error(`SSH not available on ${host}:${port} after ${maxAttempts} attempts`);
}

async function hibernateInstance(client: EC2Client, instanceId: string): Promise<void> {
  log(`Stopping instance ${instanceId}...`);
  await client.send(
    new StopInstancesCommand({
      InstanceIds: [instanceId],
      Hibernate: false, // true requires hibernate-enabled AMI + EBS encryption
    })
  );
}

async function countLocalSshConnections(host: string): Promise<number> {
  // Count local SSH processes connected to this host
  const proc = Bun.spawn(["pgrep", "-f", `ssh.*${host}`], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "ignore",
  });

  const exitCode = await proc.exited;
  if (exitCode !== 0) {
    // pgrep returns 1 when no matches found
    return 0;
  }

  const output = await new Response(proc.stdout).text();
  // Count lines (each line is a PID)
  const pids = output.trim().split("\n").filter(Boolean);
  return pids.length;
}

async function stopIfNoOtherSessions(
  client: EC2Client,
  instanceId: string,
  host: string
): Promise<void> {
  const connectionCount = await countLocalSshConnections(host);

  if (connectionCount > 0) {
    log(`Skipping stop: ${connectionCount} other SSH connection(s) to ${host} still active.`);
    return;
  }

  await hibernateInstance(client, instanceId);
}

function requireArg(value: string | undefined, label: string): string {
  if (!value) {
    throw new Error(`Missing ${label}.`);
  }
  return value;
}

async function confirm(message: string): Promise<boolean> {
  process.stdout.write(`${message} [y/N] `);

  for await (const line of console) {
    const answer = line.trim().toLowerCase();
    return answer === "y" || answer === "yes";
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Commands
// ─────────────────────────────────────────────────────────────────────────────

async function cmdInit(): Promise<void> {
  try {
    await readFile(CONFIG_PATH, "utf8");
    console.log(`Config already exists at ${CONFIG_PATH}`);
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
  await writeDefaultConfig();
  console.log(`Created config at ${CONFIG_PATH}`);
  console.log(`Edit it to set your region, instance type, AMI, and AWS credentials.`);
}

async function cmdList(config: SbxConfig): Promise<void> {
  const client = getEc2Client(config);
  const instances = await describeSbxInstances(client);
  console.log(formatInstances(instances));
}

async function cmdDelete(config: SbxConfig, name: string): Promise<void> {
  const client = getEc2Client(config);
  const instances = await describeSbxInstances(client, name);
  const instance = instances[0];
  if (!instance?.InstanceId) {
    throw new Error(`No instance found with name ${name}`);
  }
  await client.send(
    new TerminateInstancesCommand({
      InstanceIds: [instance.InstanceId],
    })
  );
  console.log(`Terminated ${name} (${instance.InstanceId}).`);
}

async function cmdResize(config: SbxConfig, name: string, sizeGb: number): Promise<void> {
  const client = getEc2Client(config);
  const instances = await describeSbxInstances(client, name);
  const instance = instances[0];

  if (!instance?.InstanceId) {
    throw new Error(`No instance found with name ${name}`);
  }

  const state = instance.State?.Name;
  if (state !== "stopped") {
    throw new Error(`Instance must be stopped to resize. Current state: ${state}`);
  }

  // Get root volume ID
  const rootDevice = instance.RootDeviceName;
  const rootMapping = instance.BlockDeviceMappings?.find(
    (m) => m.DeviceName === rootDevice
  );
  const volumeId = rootMapping?.Ebs?.VolumeId;

  if (!volumeId) {
    throw new Error("Could not find root volume for instance");
  }

  // Get current volume size
  const volumeInfo = await client.send(
    new DescribeVolumesCommand({
      VolumeIds: [volumeId],
    })
  );

  const currentSize = volumeInfo.Volumes?.[0]?.Size;
  if (!currentSize) {
    throw new Error("Could not determine current volume size");
  }

  if (sizeGb <= currentSize) {
    throw new Error(`New size (${sizeGb}GB) must be larger than current size (${currentSize}GB). EBS volumes can only be increased.`);
  }

  log(`Resizing volume ${volumeId} from ${currentSize}GB to ${sizeGb}GB...`);

  await client.send(
    new ModifyVolumeCommand({
      VolumeId: volumeId,
      Size: sizeGb,
    })
  );

  // Wait for modification to complete
  log("Waiting for volume modification to complete...");
  const maxAttempts = 60;
  for (let i = 0; i < maxAttempts; i++) {
    const mods = await client.send(
      new DescribeVolumesModificationsCommand({
        VolumeIds: [volumeId],
      })
    );

    const mod = mods.VolumesModifications?.[0];
    const modState = mod?.ModificationState;

    if (modState === "completed" || modState === "optimizing") {
      break;
    }

    if (modState === "failed") {
      throw new Error(`Volume modification failed: ${mod?.StatusMessage}`);
    }

    await Bun.sleep(5000);
  }

  console.log(`Volume resized to ${sizeGb}GB. Start the instance to apply filesystem changes.`);
}

async function cmdDestroy(config: SbxConfig): Promise<void> {
  const client = getEc2Client(config);

  // Find all sbx resources
  const instances = await describeSbxInstances(client);
  
  const vpcs = await client.send(
    new DescribeVpcsCommand({
      Filters: [{ Name: "tag:Name", Values: [SBX_TAG] }],
    })
  );
  const vpcId = vpcs.Vpcs?.[0]?.VpcId;

  const subnets = vpcId
    ? await client.send(
        new DescribeSubnetsCommand({
          Filters: [
            { Name: "vpc-id", Values: [vpcId] },
            { Name: "tag:Name", Values: [SBX_TAG] },
          ],
        })
      )
    : { Subnets: [] };

  const securityGroups = vpcId
    ? await client.send(
        new DescribeSecurityGroupsCommand({
          Filters: [
            { Name: "vpc-id", Values: [vpcId] },
            { Name: "group-name", Values: [SBX_TAG] },
          ],
        })
      )
    : { SecurityGroups: [] };

  const igws = vpcId
    ? await client.send(
        new DescribeInternetGatewaysCommand({
          Filters: [{ Name: "attachment.vpc-id", Values: [vpcId] }],
        })
      )
    : { InternetGateways: [] };

  const keyName = `sbx-${config.region}`;
  const keyPath = path.join(KEYS_DIR, `${keyName}.pem`);
  const keys = await client.send(
    new DescribeKeyPairsCommand({
      Filters: [{ Name: "key-name", Values: [keyName] }],
    })
  );

  // Show what will be deleted
  console.log("The following resources will be deleted:");
  console.log("");

  if (instances.length > 0) {
    console.log(`  Instances (${instances.length}):`);
    for (const inst of instances) {
      const name = inst.Tags?.find((t) => t.Key === "Name")?.Value ?? "unnamed";
      console.log(`    - ${name} (${inst.InstanceId})`);
    }
  }

  if (keys.KeyPairs?.length) {
    console.log(`  Key Pairs: ${keyName}`);
  }

  if (securityGroups.SecurityGroups?.length) {
    console.log(`  Security Groups: ${securityGroups.SecurityGroups[0].GroupId}`);
  }

  if (subnets.Subnets?.length) {
    console.log(`  Subnets: ${subnets.Subnets[0].SubnetId}`);
  }

  if (igws.InternetGateways?.length) {
    console.log(`  Internet Gateways: ${igws.InternetGateways[0].InternetGatewayId}`);
  }

  if (vpcId) {
    console.log(`  VPCs: ${vpcId}`);
  }

  const hasResources =
    instances.length > 0 ||
    keys.KeyPairs?.length ||
    securityGroups.SecurityGroups?.length ||
    subnets.Subnets?.length ||
    igws.InternetGateways?.length ||
    vpcId;

  if (!hasResources) {
    console.log("  (none)");
    return;
  }

  console.log("");
  const confirmed = await confirm("Are you sure you want to delete all sbx resources?");
  if (!confirmed) {
    throw new Error("Aborted.");
  }

  // 1. Terminate all instances
  if (instances.length > 0) {
    const instanceIds = instances.map((i) => i.InstanceId!);
    log(`Terminating ${instanceIds.length} instance(s)...`);
    await client.send(new TerminateInstancesCommand({ InstanceIds: instanceIds }));
    await waitUntilInstanceTerminated(
      { client, maxWaitTime: 300 },
      { InstanceIds: instanceIds }
    );
  }

  // 2. Delete key pair
  if (keys.KeyPairs?.length) {
    log(`Deleting key pair ${keyName}...`);
    await client.send(new DeleteKeyPairCommand({ KeyName: keyName }));
    try {
      await unlink(keyPath);
    } catch {
      // Key file may not exist locally
    }
  }

  // 3. Delete security group
  if (securityGroups.SecurityGroups?.length) {
    const sgId = securityGroups.SecurityGroups[0].GroupId!;
    log(`Deleting security group ${sgId}...`);
    await client.send(new DeleteSecurityGroupCommand({ GroupId: sgId }));
  }

  // 4. Delete subnet
  if (subnets.Subnets?.length) {
    const subnetId = subnets.Subnets[0].SubnetId!;
    log(`Deleting subnet ${subnetId}...`);
    await client.send(new DeleteSubnetCommand({ SubnetId: subnetId }));
  }

  // 5. Detach and delete internet gateway
  if (igws.InternetGateways?.length && vpcId) {
    const igwId = igws.InternetGateways[0].InternetGatewayId!;
    log(`Detaching internet gateway ${igwId}...`);
    await client.send(
      new DetachInternetGatewayCommand({
        InternetGatewayId: igwId,
        VpcId: vpcId,
      })
    );
    log(`Deleting internet gateway ${igwId}...`);
    await client.send(new DeleteInternetGatewayCommand({ InternetGatewayId: igwId }));
  }

  // 6. Delete VPC
  if (vpcId) {
    log(`Deleting VPC ${vpcId}...`);
    await client.send(new DeleteVpcCommand({ VpcId: vpcId }));
  }

  console.log("All sbx resources deleted.");
}

async function cmdConnect(config: SbxConfig, name: string): Promise<void> {
  const client = getEc2Client(config);
  const infra = await ensureInfrastructure(client, config.region);
  const instance = await ensureInstance(client, config, infra, name);
  const instanceId = instance.InstanceId;
  if (!instanceId) {
    throw new Error("Instance missing ID.");
  }

  const host = resolveHost(instance);

  // Wait for SSH to be ready
  await waitForSsh(host, 22, infra.keyPath, config.sshUser);

  log(`Connecting to ${host}...`);
  const sshArgs = [
    "-i",
    infra.keyPath,
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
    `${config.sshUser}@${host}`,
  ];

  await runSsh("ssh", sshArgs);

  await stopIfNoOtherSessions(client, instanceId, host);
}

async function cmdTunnel(config: SbxConfig, name: string, portMap: string): Promise<void> {
  const [local, remote] = portMap.split(":");
  if (!local || !remote) {
    throw new Error("Port map must be <local-port>:<remote-port>.");
  }

  const client = getEc2Client(config);
  const infra = await ensureInfrastructure(client, config.region);
  const instance = await ensureInstance(client, config, infra, name);
  const instanceId = instance.InstanceId;
  if (!instanceId) {
    throw new Error("Instance missing ID.");
  }

  const host = resolveHost(instance);

  // Wait for SSH to be ready
  await waitForSsh(host, 22, infra.keyPath, config.sshUser);

  log(`Tunneling localhost:${local} -> ${host}:${remote}`);
  const sshArgs = [
    "-i",
    infra.keyPath,
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
    "-L",
    `${local}:localhost:${remote}`,
    `${config.sshUser}@${host}`,
    "-N",
  ];

  await runSsh("ssh", sshArgs);

  await stopIfNoOtherSessions(client, instanceId, host);
}

async function main(): Promise<void> {
  const args = Bun.argv.slice(2);
  const command = args[0];

  if (!command || command === "-h" || command === "--help") {
    console.log(HELP_TEXT);
    return;
  }

  if (command === "init") {
    await cmdInit();
    return;
  }

  const config = await loadConfig();

  if (command === "list" || command === "ls") {
    await cmdList(config);
    return;
  }

  if (command === "delete" || command === "rm") {
    const name = requireArg(args[1], "instance name");
    await cmdDelete(config, name);
    return;
  }

  if (command === "resize") {
    const name = requireArg(args[1], "instance name");
    const sizeStr = requireArg(args[2], "size in GB");
    const sizeGb = parseInt(sizeStr, 10);
    if (isNaN(sizeGb) || sizeGb <= 0) {
      throw new Error("Size must be a positive number in GB");
    }
    await cmdResize(config, name, sizeGb);
    return;
  }

  if (command === "tunnel" || command === "proxy") {
    const name = requireArg(args[1], "instance name");
    const portMap = requireArg(args[2], "port map");
    await cmdTunnel(config, name, portMap);
    return;
  }

  if (command === "destroy") {
    await cmdDestroy(config);
    return;
  }

  // Default: connect to instance by name
  await cmdConnect(config, command);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`sbx error: ${message}`);
  process.exitCode = 1;
});
