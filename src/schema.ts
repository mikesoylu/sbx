import { z } from "zod";

export const AwsConfigSchema = z.object({
  accessKeyId: z.string().optional().describe("AWS access key ID"),
  secretAccessKey: z.string().optional().describe("AWS secret access key"),
  sessionToken: z.string().optional().describe("AWS session token (for temporary credentials)"),
  profile: z.string().optional().describe("AWS profile name from ~/.aws/credentials"),
});

export const SbxConfigSchema = z.object({
  $schema: z.string().optional().describe("JSON Schema URL for editor autocomplete"),
  region: z.string().describe("AWS region (e.g., us-east-1)"),
  instanceType: z.string().describe("EC2 instance type (e.g., t4g.micro)"),
  amiId: z.string().describe("AMI ID or alias (debian-12, ubuntu-24.04, al2023, etc.)"),
  sshUser: z.string().describe("SSH username for the AMI (e.g., admin, ubuntu, ec2-user)"),
  volumeSize: z.number().optional().describe("EBS volume size in GB (default: 8)"),
  useSpot: z.boolean().optional().describe("Use spot instances for cost savings"),
  aws: AwsConfigSchema.optional().describe("AWS credentials configuration"),
});

export type AwsConfig = z.infer<typeof AwsConfigSchema>;
export type SbxConfig = z.infer<typeof SbxConfigSchema>;
