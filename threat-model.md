# Threat Model: sample-bedrock-readiness-agent

## Application Overview

A read-only assessment agent that evaluates an AWS account's Amazon Bedrock production readiness across 6 dimensions. Built with Strands Agents SDK, runs on AgentCore Runtime. Generates findings and remediation templates (CloudFormation/Terraform) for human review.

**Data flow:** Agent → AWS APIs (read-only) → tool results → Bedrock model (Claude Sonnet 4.5, `us.` cross-Region profile) → findings report. Tool-result content (role names, spend figures, model breakdown, missing VPC endpoints) is sent to the model and may leave the source Region during cross-Region inference.

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| IAM policy documents | Role policies read during assessment | High - reveals permission structure |
| CloudWatch metrics | Throttle/invocation counts | Low - operational data |
| Service quota values | Current quota limits | Low |
| VPC endpoint configuration | Network topology indicators | Medium |
| Cost Explorer data | Spend amounts | Medium |
| Generated remediation templates | CFN/Terraform output | Low - best-practice patterns |

## STRIDE Analysis

### Spoofing

| Threat | Risk | Mitigation |
|---|---|---|
| Attacker impersonates the agent to gain API access | Low | Agent runs under AgentCore execution role with least-privilege IAM. No standalone credentials. Authentication is handled by AgentCore/IAM, not the agent code. |
| Malicious agent deployed in place of legitimate one | Low | Code published to aws-samples (audited). Deployment uses signed CFN template with fixed role permissions. |

### Tampering

| Threat | Risk | Mitigation |
|---|---|---|
| Agent modifies IAM policies or resources | None | Agent is strictly read-only. No Put/Create/Update/Delete actions in the IAM role. Enforced at IAM level, not just code level. |
| Remediation templates contain malicious content | Low | Templates are deterministic (hardcoded best-practice patterns, not dynamically generated from untrusted input). Human reviews before applying. |
| Dependencies tampered (supply chain) | Low | Only 2 dependencies (strands-agents, boto3), both pinned to exact versions, both Apache 2.0 from PyPI. |

### Repudiation

| Threat | Risk | Mitigation |
|---|---|---|
| Agent actions not logged | Low | All API calls are logged by CloudTrail automatically. AgentCore provides execution traces. |
| User denies running the assessment | Low | CloudTrail records the execution role's API calls with timestamps. |

### Information Disclosure

| Threat | Risk | Mitigation |
|---|---|---|
| Assessment findings sent to foundation model | Medium | Tool results (role names with wildcard Bedrock perms, 90-day spend figure, per-model invocation counts, missing VPC endpoints) are sent to Bedrock as tool-result messages. Raw IAM policy documents are NOT sent - they are evaluated locally and only counts are returned. |
| Cross-Region inference of prompts/results | Medium | The default model is a US cross-Region profile (`us.`). Input prompts and output results may be processed and, for abuse detection, stored in the destination Region. Accounts using SCPs to block Regions must allow every destination Region of the profile. |
| Credentials leaked in code | None | No credentials in code. Agent uses IAM execution role attached to AgentCore Runtime. |
| Findings contain sensitive account details | Low | Findings contain role names and configuration state (not secrets/keys). Findings are returned to the caller; tool-result content is also sent to the Bedrock model (see rows above). |

### Denial of Service

| Threat | Risk | Mitigation |
|---|---|---|
| Agent makes excessive API calls | Low | Assessment runs once per invocation (not continuous). ~50-100 API calls total per assessment. Well within normal rate limits. |
| Planted misconfigs throttle generator exhausts Bedrock quota | Medium | The throttle generator issues ~100 rapid invocations to force throttling. The InvokeModel quota is per-model, per-Region for the whole account, so a reader with other Bedrock traffic in the same Region (e.g. us-east-1) contends with it. Deploy only in an isolated test account and delete after use. |

### Elevation of Privilege

| Threat | Risk | Mitigation |
|---|---|---|
| Agent escalates its own permissions | None | IAM role has no iam:Put/Create/Attach actions. Cannot modify its own or any other role. |
| Remediation templates grant excessive permissions | Low | Generated templates follow least-privilege (specific actions, not wildcards). Human reviews before deployment. |
| Prompt injection causes agent to call unauthorized APIs | None | Tools are hardcoded; the LLM can only invoke the fixed tool set - no dynamic tool creation or arbitrary code execution. |
| Untrusted account content influences report integrity | Low | Role names, model IDs and endpoint names read from the account enter the prompt as tool results. A crafted resource name cannot expand the agent's permissions, but could attempt to mislead the generated report - treat the report as advisory and human-reviewed. |

## Trust Boundaries

```
┌─────────────────────────────────────────┐
│  Trust Boundary: Customer AWS Account    │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  AgentCore Runtime (isolated)     │  │
│  │  - Strands Agent                  │  │
│  │  - Fixed 7 tools                  │  │
│  │  - Least-privilege execution role │  │
│  └──────────────┬────────────────────┘  │
│                 │ (read-only APIs)       │
│  ┌──────────────▼────────────────────┐  │
│  │  AWS Services (IAM, CW, EC2, SQ)  │  │
│  └───────────────────────────────────┘  │
│                                         │
│  Output: findings returned to caller     │
│  Tool results → Bedrock model (may cross Region) │
└─────────────────────────────────────────┘
```

## Risk Summary

| Category | Overall Risk | Rationale |
|---|---|---|
| Spoofing | Low | Standard IAM auth, no custom auth |
| Tampering | None | Read-only, no write actions possible |
| Repudiation | Low | CloudTrail covers all calls |
| Information Disclosure | Medium | Model receives finding metadata (role names, spend figure); cross-Region profile |
| Denial of Service | Low | Single-run, minimal API calls |
| Elevation of Privilege | None | No write IAM permissions, fixed tool set |

**Overall assessment: LOW RISK** - The agent's read-only nature, least-privilege IAM role, fixed tool set, and local-only output eliminate most threat vectors. The primary residual risk is information disclosure of IAM policy structure, mitigated by the output staying within the customer's own account/session.

## Assumptions

- Customer deploys to their own account (not shared/multi-tenant)
- AgentCore Runtime provides network and execution isolation. Note: any code running in the microVM can read the execution role's credentials via MMDS, so isolation bounds the blast radius but is not a trust boundary against the agent's own code.
- CloudTrail is enabled in the account
- Human reviews all remediation templates before applying
- Second-order: enabling Bedrock model invocation logging (recommended by D5) persists the agent's own prompts - including role names and the spend figure - to the configured logging destination.
