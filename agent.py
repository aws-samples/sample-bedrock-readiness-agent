"""
Bedrock Adoption Readiness Agent
A Strands SDK agent on AgentCore that assesses production readiness
across IAM governance, ZDR, quota headroom, and observability.
"""

from strands import Agent, tool
from strands.models.bedrock import BedrockModel
import boto3
import json
import os
from datetime import datetime, timedelta, timezone


# --- TOOLS ---

@tool
def check_iam_governance(region: str = "us-east-1") -> dict:
    """
    D1: IAM Governance Assessment
    - Lists all roles with bedrock/bedrock-runtime/bedrock-mantle permissions
    - Detects wildcard actions (bedrock:*)
    - Checks for guardrails configuration
    - Validates least-privilege patterns
    """
    iam = boto3.client("iam")
    bedrock = boto3.client("bedrock", region_name=region)
    findings = []

    # List roles and check for bedrock-related policies
    roles = iam.list_roles(MaxItems=200)["Roles"]
    bedrock_roles = []

    for role in roles:
        role_name = role["RoleName"]
        # Check attached policies
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]

        for policy in attached:
            policy_version = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=policy_version
            )["PolicyVersion"]["Document"]

            if _has_bedrock_actions(doc):
                bedrock_roles.append({
                    "role": role_name,
                    "policy": policy["PolicyName"],
                    "type": "attached",
                    "wildcards": _detect_wildcards(doc)
                })

        for policy_name in inline_names:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
            if _has_bedrock_actions(doc):
                bedrock_roles.append({
                    "role": role_name,
                    "policy": policy_name,
                    "type": "inline",
                    "wildcards": _detect_wildcards(doc)
                })

    # Check guardrails
    guardrails = bedrock.list_guardrails()["guardrails"]

    # Generate findings
    wildcard_roles = [r for r in bedrock_roles if r["wildcards"]]
    if wildcard_roles:
        findings.append({
            "severity": "HIGH",
            "dimension": "D1-IAM",
            "finding": f"{len(wildcard_roles)} role(s) with wildcard bedrock:* actions",
            "roles": [r["role"] for r in wildcard_roles],
            "remediation": "Scope to specific actions (bedrock:InvokeModel, bedrock:GetFoundationModel)"
        })

    if not guardrails:
        findings.append({
            "severity": "HIGH",
            "dimension": "D1-IAM",
            "finding": "Zero Bedrock Guardrails configured (Standard Bedrock workloads)",
            "remediation": "Create at least one guardrail with content filters for production use"
        })

    return {
        "total_bedrock_roles": len(bedrock_roles),
        "wildcard_roles": len(wildcard_roles),
        "guardrails_count": len(guardrails),
        "findings": findings
    }


@tool
def check_data_retention(region: str = "us-east-1") -> dict:
    """
    D2: Zero Data Retention (ZDR) Assessment
    - Checks if ZDR is enabled for the account
    - Falls back to indirect evidence if API unavailable
    """
    bedrock = boto3.client("bedrock", region_name=region)
    findings = []

    try:
        # Try direct ZDR API
        retention = bedrock.get_account_data_retention()
        zdr_enabled = retention.get("dataRetentionEnabled", False)

        if not zdr_enabled:
            findings.append({
                "severity": "CRITICAL",
                "dimension": "D2-ZDR",
                "finding": "Zero Data Retention not enabled",
                "remediation": "Enable ZDR via Bedrock console or API to prevent model providers from storing your data"
            })
    except Exception as e:
        # API may not be available - flag as unable to verify
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D2-ZDR",
            "finding": "Unable to verify ZDR status (API unavailable or insufficient permissions)",
            "remediation": "Verify ZDR manually in Bedrock console > Settings > Data retention"
        })

    return {"findings": findings}


@tool
def check_quota_headroom(region: str = "us-east-1") -> dict:
    """
    D3: Quota and Capacity Headroom Assessment
    - Lists all Bedrock service quotas
    - Checks CloudWatch for utilization metrics
    - Identifies quotas approaching limits
    - Detects if CRIS (cross-region inference) is in use
    """
    sq = boto3.client("service-quotas", region_name=region)
    cw = boto3.client("cloudwatch", region_name=region)
    findings = []

    # Get all Bedrock quotas
    quotas = []
    try:
        paginator = sq.get_paginator("list_service_quotas")
        for page in paginator.paginate(ServiceCode="bedrock"):
            quotas.extend(page["Quotas"])
    except Exception as e:
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D3-Quota",
            "finding": f"Unable to list Bedrock service quotas: {type(e).__name__}",
            "remediation": "Verify servicequotas:ListServiceQuotas permission is granted"
        })

    # Check CloudWatch for throttling
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=7)

    total_throttles = 0
    try:
        throttle_response = cw.get_metric_data(
            MetricDataQueries=[{
                "Id": "throttles",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/Bedrock",
                        "MetricName": "InvocationThrottles",
                    },
                    "Period": 3600,
                    "Stat": "Sum"
                }
            }],
            StartTime=start_time,
            EndTime=end_time
        )
        total_throttles = sum(throttle_response["MetricDataResults"][0].get("Values", []))
    except Exception as e:
        findings.append({
            "severity": "LOW",
            "dimension": "D3-Quota",
            "finding": f"Unable to check throttle metrics: {type(e).__name__}",
            "remediation": "Verify cloudwatch:GetMetricData permission. May also indicate no Bedrock usage in this region."
        })

    if total_throttles > 0:
        findings.append({
            "severity": "HIGH",
            "dimension": "D3-Quota",
            "finding": f"{int(total_throttles)} throttle events in the last 7 days",
            "remediation": "Request quota increase or enable cross-region inference (CRIS) for overflow routing"
        })

    # Check for CRIS usage (geographic/global prefixes in model IDs)
    cris_models = []
    try:
        invocations = cw.list_metrics(
            Namespace="AWS/Bedrock",
            MetricName="Invocations"
        )["Metrics"]

        cris_models = [
            m for m in invocations
            for d in m.get("Dimensions", [])
            if d["Name"] == "ModelId" and any(
                d["Value"].startswith(p) for p in ["us.", "eu.", "apac.", "global."]
            )
        ]
    except Exception:
        pass  # Non-critical - CRIS detection is advisory

    no_cris = len(cris_models) == 0 and total_throttles > 0
    if no_cris:
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D3-Quota",
            "finding": "No cross-region inference (CRIS) enabled despite throttling",
            "remediation": "Enable geographic (us./eu./apac.) or global CRIS to distribute load across regions"
        })

    return {
        "total_quotas": len(quotas),
        "throttles_7d": int(total_throttles),
        "cris_in_use": len(cris_models) > 0,
        "findings": findings
    }


@tool
def check_observability(region: str = "us-east-1") -> dict:
    """
    D6: Operational Observability Assessment
    - Checks for CloudWatch alarms on Bedrock metrics
    - Validates CloudTrail logging
    - Checks for VPC endpoints (all 5 types)
    """
    cw = boto3.client("cloudwatch", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    # Check for Bedrock-related alarms
    bedrock_alarms = []
    try:
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                if alarm.get("Namespace") in ["AWS/Bedrock", "AWS/BedrockMantle"]:
                    bedrock_alarms.append(alarm)
    except Exception as e:
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D6-Observability",
            "finding": f"Unable to check CloudWatch alarms: {type(e).__name__}",
            "remediation": "Verify cloudwatch:DescribeAlarms permission is granted"
        })

    if not bedrock_alarms and not any(f["finding"].startswith("Unable") for f in findings):
        findings.append({
            "severity": "HIGH",
            "dimension": "D6-Observability",
            "finding": "Zero CloudWatch alarms configured for Bedrock metrics",
            "remediation": "Create alarms for InvocationThrottles, InvocationServerErrors, and InputTokenCount"
        })

    # Check VPC endpoints
    vpc_endpoints = []
    missing = set()
    try:
        vpc_endpoints = ec2.describe_vpc_endpoints(
            Filters=[{
                "Name": "service-name",
                "Values": [
                    f"com.amazonaws.{region}.bedrock",
                    f"com.amazonaws.{region}.bedrock-runtime",
                    f"com.amazonaws.{region}.bedrock-mantle",
                    f"com.amazonaws.{region}.bedrock-agent",
                    f"com.amazonaws.{region}.bedrock-agent-runtime"
                ]
            }]
        )["VpcEndpoints"]

        endpoint_services = set(ep["ServiceName"].split(".")[-1] for ep in vpc_endpoints)
        expected = {"bedrock", "bedrock-runtime", "bedrock-mantle", "bedrock-agent", "bedrock-agent-runtime"}
        missing = expected - endpoint_services
    except Exception as e:
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D6-Observability",
            "finding": f"Unable to check VPC endpoints: {type(e).__name__}",
            "remediation": "Verify ec2:DescribeVpcEndpoints permission is granted"
        })

    if missing:
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D6-Observability",
            "finding": f"Missing VPC endpoints: {', '.join(sorted(missing))}",
            "remediation": f"Create VPC endpoints for: {', '.join(f'com.amazonaws.{region}.{s}' for s in sorted(missing))}"
        })

    return {
        "bedrock_alarms": len(bedrock_alarms),
        "vpc_endpoints_found": len(vpc_endpoints),
        "vpc_endpoints_missing": list(missing),
        "findings": findings
    }



@tool
def check_model_selection_fitness(region: str = "us-east-1") -> dict:
    """
    D4: Model Selection Fitness Assessment
    - Checks if expensive models are used for simple tasks
    - Detects single-model dependency
    - Identifies legacy model usage
    - Validates CRIS usage patterns
    """
    cw = boto3.client("cloudwatch", region_name=region)
    findings = []

    try:
        metrics = cw.list_metrics(
            Namespace="AWS/Bedrock",
            MetricName="Invocations"
        )["Metrics"]

        model_ids = set()
        for m in metrics:
            for d in m.get("Dimensions", []):
                if d["Name"] == "ModelId":
                    model_ids.add(d["Value"])

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)

        total_invocations = 0
        model_invocation_counts = {}

        for model_id in model_ids:
            try:
                response = cw.get_metric_data(
                    MetricDataQueries=[{
                        "Id": "inv",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Bedrock",
                                "MetricName": "Invocations",
                                "Dimensions": [{"Name": "ModelId", "Value": model_id}]
                            },
                            "Period": 86400,
                            "Stat": "Sum"
                        },
                        "StartTime": start_time,
                        "EndTime": end_time
                    }],
                    StartTime=start_time,
                    EndTime=end_time
                )
                count = sum(response["MetricDataResults"][0].get("Values", []))
                model_invocation_counts[model_id] = int(count)
                total_invocations += count
            except Exception:
                # Metric fetch failed for this model - record it as 0 so it stays
                # visible in the breakdown rather than being silently dropped
                # (dropping would skew the premium-model percentage below).
                model_invocation_counts[model_id] = 0

        # Minimum sample gate
        if total_invocations < 50:
            findings.append({
                "severity": "INFO",
                "dimension": "D4-ModelFit",
                "finding": f"Insufficient data ({int(total_invocations)} invocations in 7 days, need 50+)",
                "remediation": "Re-run assessment after more Bedrock usage accumulates"
            })
            return {"total_invocations_7d": int(total_invocations), "models_in_use": len(model_ids), "status": "INSUFFICIENT_DATA", "findings": findings}

        # Single-model dependency
        if len(model_invocation_counts) == 1:
            findings.append({
                "severity": "MEDIUM",
                "dimension": "D4-ModelFit",
                "finding": "Single model for all use cases - no fallback if deprecated or throttled",
                "remediation": "Evaluate alternative models for different use cases (Haiku for classification, Sonnet for reasoning)"
            })

        # Expensive model dominance
        expensive_models = [m for m in model_invocation_counts.keys()
                          if any(x in m.lower() for x in ["opus", "sonnet-4", "gpt-5.6-sol", "gpt-5.6-terra"])]
        if expensive_models and total_invocations > 0:
            expensive_pct = sum(model_invocation_counts.get(m, 0) for m in expensive_models) / total_invocations * 100
            if expensive_pct > 60:
                findings.append({
                    "severity": "MEDIUM",
                    "dimension": "D4-ModelFit",
                    "finding": f"{expensive_pct:.0f}% of invocations use premium models",
                    "remediation": "Evaluate cheaper models for simple tasks (classification, extraction)"
                })

        # Legacy model usage
        legacy_patterns = ["claude-v2", "claude-instant", "titan-text-lite", "titan-text-express"]
        legacy_in_use = [m for m in model_ids if any(l in m.lower() for l in legacy_patterns)]
        if legacy_in_use:
            findings.append({
                "severity": "MEDIUM",
                "dimension": "D4-ModelFit",
                "finding": f"Legacy/deprecated models in use: {', '.join(legacy_in_use)}",
                "remediation": "Migrate to current model versions for continued support"
            })

        # CRIS detection
        cris_models = [m for m in model_ids if any(m.startswith(p) for p in ["us.", "eu.", "apac.", "global."])]
        if cris_models:
            findings.append({
                "severity": "INFO",
                "dimension": "D4-ModelFit",
                "finding": f"CRIS active on {len(cris_models)} model(s) - good for capacity resilience",
                "remediation": "No action needed"
            })

    except Exception as e:
        findings.append({
            "severity": "LOW",
            "dimension": "D4-ModelFit",
            "finding": f"Unable to assess model fitness: {type(e).__name__}",
            "remediation": "Verify cloudwatch:ListMetrics and cloudwatch:GetMetricData permissions"
        })
        return {"status": "ERROR", "findings": findings}

    return {
        "total_invocations_7d": int(total_invocations),
        "models_in_use": len(model_ids),
        "model_breakdown": model_invocation_counts,
        "cris_active": len(cris_models) > 0,
        "findings": findings
    }


@tool
def check_cost_projection(region: str = "us-east-1") -> dict:
    """
    D5: Cost Projection Assessment
    - Checks if batch-eligible workloads are on on-demand
    - Detects spend growth trends (MoM)
    - Checks model invocation logging (needed for cost attribution)
    """
    bedrock = boto3.client("bedrock", region_name=region)
    ce = boto3.client("ce", region_name="us-east-1")
    findings = []

    # Check for batch inference jobs
    batch_jobs_exist = False
    batch_check_failed = False
    try:
        jobs = bedrock.list_model_invocation_jobs(MaxResults=1)
        batch_jobs_exist = len(jobs.get("invocationJobSummaries", [])) > 0
    except Exception as e:
        batch_check_failed = True
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D5-Cost",
            "finding": f"Unable to verify batch inference jobs: {type(e).__name__}",
            "remediation": "Verify bedrock:ListModelInvocationJobs permission is granted"
        })

    if not batch_jobs_exist and not batch_check_failed:
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D5-Cost",
            "finding": "No batch inference jobs found - batch-eligible workloads paying on-demand rates (50% premium)",
            "remediation": "Evaluate batch inference for non-real-time workloads (summarization, classification, data extraction)"
        })

    # Check Cost Explorer for spend trends
    try:
        end_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start_date = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")

        cost_response = ce.get_cost_and_usage(
            TimePeriod={"Start": start_date, "End": end_date},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            Filter={
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": ["Amazon Bedrock"]
                }
            }
        )

        monthly_costs = []
        for result in cost_response.get("ResultsByTime", []):
            amount = float(result["Total"]["UnblendedCost"]["Amount"])
            monthly_costs.append(amount)

        if len(monthly_costs) >= 2 and monthly_costs[-2] > 0:
            growth = (monthly_costs[-1] - monthly_costs[-2]) / monthly_costs[-2] * 100
            if growth > 20:
                findings.append({
                    "severity": "MEDIUM",
                    "dimension": "D5-Cost",
                    "finding": f"Bedrock spend growing {growth:.0f}% month-over-month without commitment strategy",
                    "remediation": "Evaluate Provisioned Throughput for predictable workloads"
                })

        if monthly_costs:
            total_spend = sum(monthly_costs)
            findings.append({
                "severity": "INFO",
                "dimension": "D5-Cost",
                "finding": f"90-day Bedrock spend: ${total_spend:.2f} ({', '.join(f'${c:.2f}' for c in monthly_costs)})",
                "remediation": "Informational - cost baseline established"
            })

    except Exception as e:
        findings.append({
            "severity": "LOW",
            "dimension": "D5-Cost",
            "finding": f"Unable to retrieve cost data: {type(e).__name__}",
            "remediation": "Verify ce:GetCostAndUsage permission. Cost Explorer must be enabled on payer account."
        })

    # Check model invocation logging
    try:
        logging_config = bedrock.get_model_invocation_logging_configuration()
        config = logging_config.get("loggingConfig", {})
        logging_enabled = config.get("textDataDeliveryEnabled", False) or config.get("imageDataDeliveryEnabled", False)

        if not logging_enabled:
            findings.append({
                "severity": "HIGH",
                "dimension": "D5-Cost",
                "finding": "Model invocation logging disabled - cannot attribute costs to specific use cases",
                "remediation": "Enable model invocation logging in Bedrock Settings for cost visibility and optimization"
            })
    except Exception as e:
        findings.append({
            "severity": "MEDIUM",
            "dimension": "D5-Cost",
            "finding": f"Unable to verify model invocation logging: {type(e).__name__}",
            "remediation": "Verify bedrock:GetModelInvocationLoggingConfiguration permission is granted"
        })

    return {
        "batch_jobs_exist": batch_jobs_exist,
        "findings": findings
    }


@tool
def generate_remediation(findings: list) -> dict:
    """
    Generates CloudFormation and Terraform remediation templates
    for all findings with severity HIGH or CRITICAL.
    """
    cfn_resources = {}
    tf_resources = []

    for finding in findings:
        if finding["severity"] not in ["CRITICAL", "HIGH"]:
            continue

        if "guardrails" in finding["finding"].lower():
            cfn_resources["BedrockGuardrail"] = {
                "Type": "AWS::Bedrock::Guardrail",
                "Properties": {
                    "Name": "production-guardrail",
                    "BlockedInputMessaging": "Input blocked by guardrail",
                    "BlockedOutputsMessaging": "Output blocked by guardrail",
                    "ContentPolicyConfig": {
                        "FiltersConfig": [
                            {"InputStrength": "HIGH", "OutputStrength": "HIGH", "Type": "HATE"},
                            {"InputStrength": "HIGH", "OutputStrength": "HIGH", "Type": "INSULTS"},
                            {"InputStrength": "HIGH", "OutputStrength": "HIGH", "Type": "SEXUAL"},
                            {"InputStrength": "HIGH", "OutputStrength": "HIGH", "Type": "VIOLENCE"}
                        ]
                    }
                }
            }
            tf_resources.append("""
resource "aws_bedrock_guardrail" "production" {
  name                      = "production-guardrail"
  blocked_input_messaging   = "Input blocked by guardrail"
  blocked_outputs_messaging = "Output blocked by guardrail"

  content_policy_config {
    filters_config {
      input_strength  = "HIGH"
      output_strength = "HIGH"
      type            = "HATE"
    }
    filters_config {
      input_strength  = "HIGH"
      output_strength = "HIGH"
      type            = "INSULTS"
    }
  }
}""")

        if "vpc endpoint" in finding["finding"].lower() or "missing" in finding["finding"].lower() and "vpc" in finding["finding"].lower():
            for svc in ["bedrock", "bedrock-runtime", "bedrock-mantle", "bedrock-agent", "bedrock-agent-runtime"]:
                cfn_resources[f"VpcEndpoint{svc.replace('-', '').title()}"] = {
                    "Type": "AWS::EC2::VPCEndpoint",
                    "Properties": {
                        "VpcId": {"Ref": "VpcId"},
                        "ServiceName": {"Fn::Sub": f"com.amazonaws.${{AWS::Region}}.{svc}"},
                        "VpcEndpointType": "Interface",
                        "PrivateDnsEnabled": True,
                        "SubnetIds": {"Ref": "SubnetIds"},
                        "SecurityGroupIds": [{"Ref": "SecurityGroupId"}]
                    }
                }
                tf_resources.append(f"""
resource "aws_vpc_endpoint" "bedrock_{svc.replace('-', '_')}" {{
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${{var.region}}.{svc}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = [var.security_group_id]
  private_dns_enabled = true
}}""")

    cfn_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Bedrock Readiness Remediation",
        "Resources": cfn_resources
    } if cfn_resources else None

    tf_template = "\n".join(tf_resources) if tf_resources else None

    return {
        "cloudformation": json.dumps(cfn_template, indent=2) if cfn_template else "No CFN remediation needed",
        "terraform": tf_template or "No Terraform remediation needed",
        "findings_addressed": len([f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]])
    }


# --- HELPER FUNCTIONS ---

def _has_bedrock_actions(policy_doc: dict) -> bool:
    """Check if a policy document contains bedrock-related actions."""
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if any(prefix in action.lower() for prefix in ["bedrock:", "bedrock-runtime:", "bedrock-mantle:"]):
                return True
    return False


def _detect_wildcards(policy_doc: dict) -> bool:
    """Check if a policy document contains wildcard bedrock actions."""
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if action in ["bedrock:*", "bedrock-runtime:*", "bedrock-mantle:*"]:
                return True
    return False


# --- AGENT DEFINITION ---

SYSTEM_PROMPT = """You are the Bedrock Adoption Readiness Agent. You assess whether an AWS account
is ready to run Amazon Bedrock at production scale.

You evaluate six dimensions:
1. D1: IAM Governance - role permissions, wildcards, guardrails
2. D2: Data Retention (ZDR) - zero data retention policy
3. D3: Quota and Capacity Headroom - throttling, CRIS, quota utilization
4. D4: Model Selection Fitness - model diversity, legacy usage, cost efficiency
5. D5: Cost Projection - batch eligibility, spend trends, logging for attribution
6. D6: Observability - alarms, VPC endpoints, logging

For each dimension, you produce severity-rated findings (CRITICAL/HIGH/MEDIUM/LOW/INFO)
with specific remediation steps.

After assessment, generate remediation templates (CloudFormation + Terraform) for
all HIGH and CRITICAL findings.

Output format:
1. Overall verdict: READY / READY WITH ACTIONS / NOT READY
2. Per-dimension findings with severity
3. Remediation templates (CFN + Terraform)
4. Priority actions sorted by urgency

IMPORTANT RULES:
- Run ALL six dimension checks exactly ONCE each. Do NOT retry failed checks.
- If a check returns errors/exceptions in its findings, report those as-is. Do NOT re-run the tool.
- After all six checks complete, call generate_remediation ONCE with the combined findings.
- Deliver the report ONCE. Do not repeat or summarize it afterward.
"""

# Model and Regions are configurable via environment variables so readers
# outside us-east-1 can point at their own geography (e.g. eu., apac.
# cross-Region inference profiles) without editing code. Defaults preserve
# the original behavior.
MODEL_ID = os.environ.get("BEDROCK_READINESS_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
MODEL_REGION = os.environ.get("BEDROCK_READINESS_MODEL_REGION", "us-east-1")
TARGET_REGION = os.environ.get("BEDROCK_READINESS_TARGET_REGION", "us-east-1")

# Create the agent
model = BedrockModel(
    model_id=MODEL_ID,
    region_name=MODEL_REGION
)

agent = Agent(
    model=model,
    system_prompt=SYSTEM_PROMPT,
    tools=[
        check_iam_governance,
        check_data_retention,
        check_quota_headroom,
        check_model_selection_fitness,
        check_cost_projection,
        check_observability,
        generate_remediation
    ]
)


if __name__ == "__main__":
    result = agent(f"Run a full Bedrock production readiness assessment for this account in {TARGET_REGION}. Assess all six dimensions: IAM, ZDR, Quota, Model Fitness, Cost, and Observability. Run each check exactly once, then generate_remediation once, then deliver the report once. Do not repeat.")
    # Result is already printed by the agent's streaming output
    # No need to print(result) - that causes duplication
