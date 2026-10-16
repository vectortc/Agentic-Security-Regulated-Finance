"""casebound: case-bound control invariants (C1-C5) and audit reconstruction for LLM agents.

Algorithm map: policy.retrieve_current_policy (3), redaction.redact_before_inference (4),
gateway.invoke_controlled_tool (2), workflow.execute_regulated_workflow (1), reconstruct.reconstruct (5).
"""
from .events import Event, EventType, digest
from .evidence import adverse_action_statement, art12_record
from .gateway import StaticAuthorizer, ToolRegistry, invoke_controlled_tool
from .ledger import InMemoryLedger, Ledger, SQLiteLedger
from .llm import LLMDecider, LLMPlanner
from .model import GatedModelAdapter
from .policy import InMemoryPolicyStore, make_version, retrieve_current_policy
from .ports import (AuthorizationError, ControlException, Decision, InferenceBoundaryError, ModelBackedDecider,
                    ModelBackedPlanner, ModelClient, ModelOutputError, ModelRequest, ModelResponse, Plan,
                    PolicyEvidence, PolicyVersion, RedactionEvidence, ToolAdapter, ToolStep)
from .reconstruct import (COMPLETE, FAILED, INCOMPLETE, LINE9_STATUS, PLAN_COMMITMENT, Verdict, phi,
                          reconcile, reconstruct)
from .redaction import (AllowRedactedOnly, ExtractionSchema, classify_boundary, redact_before_inference, scan_payload_pii,
                        scan_payload_pii_deep)
from .workflow import (Outcome, Request, WorkflowContext, execute_regulated_workflow,
                       record_review_decision, steps_for)

__version__ = "0.3.0"
__all__ = [n for n in dir() if not n.startswith("_")]
