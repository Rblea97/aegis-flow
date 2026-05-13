from dataclasses import dataclass, field
from typing import Literal

PlaybookType = Literal["COMPUTE", "IDENTITY"]

@dataclass
class RemediationContext:
    resource_arn: str
    finding_id: str
    finding_type: str
    playbook_type: PlaybookType
    action: str
    instance_id: str = ""
    eni_id: str = ""
    principal_arn: str = ""
    session_context: dict = field(default_factory=dict)
