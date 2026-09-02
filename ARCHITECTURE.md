# Architecture

## Overview

The Bedrock Readiness Agent is a standalone Python application built with the [Strands Agents SDK](https://github.com/strands-agents/strands-agents-python) that runs on [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock/latest/userguide/agentcore.html). It performs a read-only assessment of an AWS account's Bedrock production readiness across six dimensions.

## Architecture Diagram

```
                    ┌─────────────────────────────────────┐
                    │         Customer AWS Account         │
                    └─────────────────────────────────────┘
                                     │
                                     ▼
                    ┌─────────────────────────────────────┐
                    │      AgentCore Runtime               │
                    │  ┌───────────────────────────────┐  │
                    │  │   Bedrock Readiness Agent      │  │
                    │  │   (Strands SDK / Python)       │  │
                    │  │                               │  │
                    │  │   ┌─────────┐ ┌────────────┐  │  │
                    │  │   │ Claude  │ │   7 Tools  │  │  │
                    │  │   │ Sonnet  │ │            │  │  │
                    │  │   └────┬────┘ └─────┬──────┘  │  │
                    │  └────────┼─────────────┼────────┘  │
                    └───────────┼─────────────┼───────────┘
                                │             │
                    ┌───────────┼─────────────┼───────────┐
                    │           ▼             ▼           │
                    │     ┌──────────┐  ┌──────────┐     │
                    │     │ Bedrock  │  │ AWS APIs │     │
                    │     │ Converse │  │(Read-Only)│     │
                    │     └──────────┘  └──────────┘     │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │       Read-Only APIs         │   │
                    │  ├─────────────────────────────┤   │
                    │  │ IAM          │ ServiceQuotas│   │
                    │  │ - ListRoles  │ - ListQuotas │   │
                    │  │ - GetPolicy  │ - GetQuota   │   │
                    │  ├─────────────────────────────┤   │
                    │  │ Bedrock      │ CloudWatch   │   │
                    │  │ - ListModels │ - GetMetrics │   │
                    │  │ - GetConfig  │ - DescAlarms │   │
                    │  ├─────────────────────────────┤   │
                    │  │ EC2          │ Cost Explorer│   │
                    │  │ - DescVPCE   │ - GetCost    │   │
                    │  └─────────────────────────────┘   │
                    │         Customer AWS Account         │
                    └─────────────────────────────────────┘

                                     │
                                     ▼
                    ┌─────────────────────────────────────┐
                    │            Output                    │
                    ├─────────────────────────────────────┤
                    │  - Severity-rated findings           │
                    │  - CloudFormation templates          │
                    │  - Terraform configurations          │
                    │  - Priority action list              │
                    │  - Readiness score (0-100)           │
                    └─────────────────────────────────────┘
```

## Agent Flow

```
User Prompt
    │
    ▼
┌──────────────────────┐
│  Strands Agent Loop   │
│  (Claude Sonnet 4.5) │
└──────────┬───────────┘
           │
           ├── Tool 1: check_iam_governance()
           │     └── IAM ListRoles → GetPolicy → detect wildcards + guardrails
           │
           ├── Tool 2: check_data_retention()
           │     └── Bedrock GetAccountDataRetention → verify ZDR
           │
           ├── Tool 3: check_quota_headroom()
           │     └── ServiceQuotas List → CloudWatch throttle metrics → CRIS detection
           │
           ├── Tool 4: check_model_selection_fitness()
           │     └── CloudWatch per-model invocations → legacy/diversity/cost analysis
           │
           ├── Tool 5: check_cost_projection()
           │     └── Cost Explorer trends → batch jobs check → invocation logging
           │
           ├── Tool 6: check_observability()
           │     └── CloudWatch DescribeAlarms → EC2 DescribeVpcEndpoints
           │
           └── Tool 7: generate_remediation()
                 └── Combine findings → generate CFN + Terraform templates
                       │
                       ▼
              ┌─────────────────┐
              │  Final Report    │
              │  (Markdown)      │
              └─────────────────┘
```

## Design Decisions

### Read-Only Throughout

All API calls are describe/list/get operations. The agent never modifies resources. Remediation templates are generated for human review - the agent proposes, the human applies.

### Strands SDK + AgentCore

The agent uses the Strands Agents SDK for tool orchestration and runs on AgentCore Runtime. This gives customers:
- Managed execution environment (no infra to maintain)
- Built-in auth and networking
- Automatic scaling

### Six Dimensions

| Dimension | What It Checks | Why It Matters |
|---|---|---|
| D1: IAM Governance | Wildcard permissions, guardrails | Prevents over-permissioned access and harmful content |
| D2: Data Retention | ZDR configuration | Ensures data isn't stored by model providers |
| D3: Quota Headroom | Throttle history, CRIS usage | Prevents production outages from quota exhaustion |
| D4: Model Fitness | Model diversity, legacy usage | Avoids single-model dependency and deprecated paths |
| D5: Cost Projection | Batch eligibility, spend trends, logging | Prevents cost surprises at scale |
| D6: Observability | Alarms, VPC endpoints | Ensures operational visibility before production |

### Graceful Degradation

Every tool wraps its API calls in try/except. If a permission is missing or an API fails, the dimension reports what it could not assess rather than crashing. The agent always produces a complete report.

### Dual-Surface Coverage

The agent assesses both Standard Bedrock (`bedrock-runtime`) and Mantle (`bedrock-mantle` / OpenAI-compatible) surfaces. Most tools only cover one.

### Cross-Region Inference Detection

The agent detects CRIS usage by checking for geographic (`us.`, `eu.`, `apac.`) and global (`global.`) prefixes in CloudWatch ModelId dimensions. This is a readiness strength signal (capacity resilience).

## Security

- **No credentials stored in code** - uses the execution role attached to AgentCore Runtime
- **Least-privilege IAM role** - only describe/list/get actions (see template.yaml)
- **No customer data persisted by the agent** - findings exist only in the session output. Note: tool results (role names, spend figure, model breakdown) are sent to the Bedrock model, and if the operator enables Bedrock model invocation logging (recommended by D5 for cost attribution), those prompts are persisted to the configured logging destination.
- **Planted misconfigs are isolated** - demo stack deploys to a separate test environment

## Cost Estimate

| Component | Per Assessment |
|---|---|
| Bedrock (Claude Sonnet, ~2K input + ~4K output tokens) | ~$0.02-0.05 |
| CloudWatch GetMetricData (7-day window) | ~$0.01 |
| IAM/EC2/ServiceQuotas API calls | Free tier |
| **Total per assessment** | **~$0.03-0.06** |

Running daily across 10 accounts: ~$9-18/month.

## Project Structure

```
sample-bedrock-readiness-agent/
├── agent.py                  # Strands agent + tool functions
├── template.yaml             # AgentCore deployment (CFN)
├── planted-misconfigs.yaml   # Intentionally broken env for testing
├── threat-model.md           # STRIDE threat model
├── requirements.txt          # Pinned dependencies
├── README.md                 # Quick start + usage
├── ARCHITECTURE.md           # This file
├── LICENSE                   # MIT-0
├── NOTICE
├── CODE_OF_CONDUCT.md
└── CONTRIBUTING.md
```

## Future Directions

| Version | Additions |
|---|---|
| v2 | Multi-account org rollup, pre-deploy CI/CD gate |
| v3 | Continuous monitoring, learning loop (resolved findings adjust thresholds) |
