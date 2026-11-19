"""Allowlisted remediation actions, their risk tiers and the (simulated) executor.

The LLM can only *suggest* action types from this catalog. Risk is always taken from the
catalog, never from model output, so a prompt-injected incident cannot downgrade risk or
invent a new action.
"""

from dataclasses import dataclass

from app.models import Category, Risk, Role


@dataclass(frozen=True)
class ActionSpec:
    description: str
    risk: Risk
    auto_approve: bool = False


ACTION_CATALOG: dict[str, ActionSpec] = {
    "collect_diagnostics": ActionSpec(
        "Collect read-only diagnostics (logs, metrics snapshot, recent events)", Risk.low, auto_approve=True
    ),
    "restart_service": ActionSpec("Perform a rolling restart of the affected service", Risk.medium),
    "scale_out": ActionSpec("Add capacity by scaling out the affected service", Risk.medium),
    "clear_disk_space": ActionSpec("Rotate and compress logs, purge temp files on the affected hosts", Risk.medium),
    "enable_degraded_mode": ActionSpec("Enable a degraded-mode feature flag to bypass a failing dependency", Risk.medium),
    "rollback_deployment": ActionSpec("Roll the service back to the previous known-good release", Risk.high),
    "failover_database": ActionSpec("Promote the standby database to primary", Risk.high),
    "rotate_credentials": ActionSpec("Rotate service credentials and invalidate active sessions", Risk.high),
    "block_traffic_source": ActionSpec("Block a suspicious traffic source at the edge", Risk.high),
}

CATEGORY_DEFAULT_ACTIONS: dict[Category, list[str]] = {
    Category.database: ["collect_diagnostics", "failover_database"],
    Category.network: ["collect_diagnostics", "restart_service"],
    Category.memory: ["collect_diagnostics", "restart_service", "scale_out"],
    Category.cpu: ["collect_diagnostics", "scale_out"],
    Category.disk: ["collect_diagnostics", "clear_disk_space"],
    Category.deployment: ["collect_diagnostics", "rollback_deployment"],
    Category.security: ["collect_diagnostics", "rotate_credentials", "block_traffic_source"],
    Category.dependency: ["collect_diagnostics", "enable_degraded_mode"],
    Category.unknown: ["collect_diagnostics"],
}

# Minimum role allowed to approve an action of a given risk (least privilege).
APPROVER_ROLE: dict[Risk, Role] = {Risk.low: Role.responder, Risk.medium: Role.responder, Risk.high: Role.admin}


def execute_action(action_type: str, target: str, mode: str) -> tuple[bool, str]:
    """Run an approved action. Only the safe, simulated executor ships with OpsPilot.

    Real integrations (Kubernetes, cloud APIs, ...) plug in here; they must keep the allowlist check.
    """
    spec = ACTION_CATALOG.get(action_type)
    if spec is None:
        return False, f"Refused: '{action_type}' is not an allowlisted action"
    if mode == "disabled":
        return False, "Execution is disabled by configuration (EXECUTOR_MODE=disabled)"
    if mode != "simulate":
        return False, f"Unsupported executor mode '{mode}'"
    return True, f"[simulated] {spec.description} -> target={target}"
