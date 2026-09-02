# Bedrock Readiness Agent

> **This is sample code, for non-production usage.** You should work with your security and legal teams to meet your organizational security, regulatory, and compliance requirements before deployment.

Assess whether your AWS account is ready to run Amazon Bedrock at production scale.

## What this is

A standalone assessment agent built with the [Strands Agents SDK](https://github.com/strands-agents/strands-agents-python) that evaluates your Bedrock environment across six dimensions: IAM governance, data retention, quota headroom, model selection fitness, cost projection, and operational observability. It generates severity-rated findings with remediation templates (CloudFormation and Terraform) you can apply directly.

The agent runs on [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock/latest/userguide/agentcore.html) or locally with AWS credentials. It is **read-only** - it queries your configuration and metrics but never modifies resources.

## How it works

```
Prompt → Agent (Claude Sonnet) → 6 Assessment Tools → Findings + Remediation Templates
```

| Phase | What happens | APIs used |
|---|---|---|
| D1: IAM Governance | Scans roles for wildcard permissions, checks guardrails | IAM, Bedrock |
| D2: Data Retention | Verifies Zero Data Retention (ZDR) configuration | Bedrock |
| D3: Quota Headroom | Checks throttle history, detects CRIS usage | ServiceQuotas, CloudWatch |
| D4: Model Fitness | Analyzes model diversity, legacy usage, cost efficiency | CloudWatch |
| D5: Cost Projection | Checks batch eligibility, spend trends, invocation logging | Cost Explorer, Bedrock |
| D6: Observability | Validates alarms exist, checks all 5 VPC endpoint types | CloudWatch, EC2 |
| Remediation | Generates CFN + Terraform for HIGH/CRITICAL findings | N/A (output only) |

## Prerequisites

- Python 3.12+
- AWS credentials with read-only access to: IAM, Bedrock, CloudWatch, EC2, ServiceQuotas, Cost Explorer
- Amazon Bedrock model access enabled (Claude Sonnet)

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the assessment
python agent.py
```

## Configuration (optional)

The reasoning model and Regions are environment-variable driven, with defaults that preserve the original behavior. Readers outside `us-east-1` can point at their own geography without editing code:

| Variable | Default | Purpose |
|---|---|---|
| `BEDROCK_READINESS_MODEL_ID` | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` | Reasoning model (a US cross-Region inference profile). Set an `eu.` / `apac.` profile for other geos. |
| `BEDROCK_READINESS_MODEL_REGION` | `us-east-1` | Region the reasoning model is invoked in. |
| `BEDROCK_READINESS_TARGET_REGION` | `us-east-1` | Region the assessment runs against. |

## Deploy to AgentCore

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name bedrock-readiness-agent \
  --parameter-overrides \
    VpcId=<your-vpc-id> \
    SubnetIds=<subnet-1>,<subnet-2> \
    SecurityGroupId=<sg-id> \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

## Test with planted misconfigurations

Deploy a deliberately misconfigured environment to validate the agent finds the right issues:

```bash
aws cloudformation deploy \
  --template-file planted-misconfigs.yaml \
  --stack-name bedrock-readiness-demo \
  --parameter-overrides VpcId=<your-vpc-id> \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

Expected findings after deployment:
- D1: 2+ roles with wildcard `bedrock:*` permissions
- D1: Zero guardrails configured
- D6: Zero CloudWatch alarms for Bedrock metrics
- D6: All 5 VPC endpoints missing

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

```
Customer Account
    │
    ▼
AgentCore Runtime
    │
    ├── Strands Agent (Claude Sonnet)
    │       │
    │       ├── check_iam_governance()      → IAM APIs
    │       ├── check_data_retention()      → Bedrock APIs
    │       ├── check_quota_headroom()      → ServiceQuotas + CloudWatch
    │       ├── check_model_selection_fitness() → CloudWatch
    │       ├── check_cost_projection()     → Cost Explorer + Bedrock
    │       ├── check_observability()       → CloudWatch + EC2
    │       └── generate_remediation()      → CFN/Terraform output
    │
    ▼
Findings Report + Remediation Templates
```

## Output

The agent produces:
- Overall readiness verdict (READY / READY WITH ACTIONS / NOT READY)
- Per-dimension severity-rated findings (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- CloudFormation remediation template
- Terraform remediation template
- Priority action list sorted by urgency
- Readiness score breakdown (0-100 per dimension)

## Cost

| Component | Per assessment |
|---|---|
| Bedrock (Claude Sonnet, ~6K tokens) | ~$0.03-0.06 |
| CloudWatch / IAM / EC2 API calls | Free tier |
| **Total (agent run)** | **~$0.03-0.06** |

Testing/demo add-ons (not part of a normal assessment run):

| Component | Cost |
|---|---|
| Planted-misconfigs demo stack (3 IAM roles + 1 Lambda) | Negligible; delete after use |
| Throttle generator (~100 Bedrock invocations) | ~$0.01-0.05 per run, model-dependent |

## Directory structure

```
sample-bedrock-readiness-agent/
├── agent.py                    # Agent + tool functions
├── template.yaml               # AgentCore deployment (CFN)
├── planted-misconfigs.yaml     # Intentionally broken env for testing
├── threat-model.md             # STRIDE threat model
├── ARCHITECTURE.md             # Design documentation
├── README.md                   # Quick start + usage
├── requirements.txt            # Pinned dependencies
├── LICENSE                     # MIT-0
├── NOTICE
├── CODE_OF_CONDUCT.md
└── CONTRIBUTING.md
```

## Key design decisions

- **Read-only throughout** - agent proposes remediation, human applies
- **Graceful degradation** - missing permissions produce findings, not crashes
- **Dual-surface coverage** - assesses both Standard Bedrock and Mantle (OpenAI-compatible)
- **CRIS detection** - identifies geographic (`us.`, `eu.`, `apac.`) and global (`global.`) cross-region inference
- **Pinned dependencies** - strands-agents 0.1.5, boto3 1.35.0

## Cleanup

```bash
# Remove planted misconfigs
aws cloudformation delete-stack --stack-name bedrock-readiness-demo --region us-east-1

# Remove agent (if deployed to AgentCore)
aws cloudformation delete-stack --stack-name bedrock-readiness-agent --region us-east-1
```

## Security Considerations

- **Read-only execution.** The role grants only describe/list/get plus `bedrock:InvokeModel`; enforced in IAM, not just code.
- **Confused-deputy prevention.** The AgentCore trust policy is scoped with `aws:SourceAccount` / `aws:SourceArn`.
- **IAM policy structure is read.** The agent reads IAM policy documents locally and returns only counts, not raw documents.
- **Cross-Region inference.** The default model is a US cross-Region profile (`us.anthropic.claude-sonnet-4-5-...`); prompts and results may leave the source Region. Set `BEDROCK_READINESS_MODEL_ID` / `BEDROCK_READINESS_MODEL_REGION` (see Configuration) to point at another geography.

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) to report security issues.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
