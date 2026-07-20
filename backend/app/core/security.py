"""AegisGrid Security and RBAC Middleware Verification Module.

Intercepts requests and verifies that the calling entity contains valid
permissions defined under Role-Based Access Control (RBAC).
"""

import logging
from typing import List
from fastapi import Header, HTTPException, status, Depends

logger = logging.getLogger("aegisgrid.security")


class RoleVerifier:
    """Verifies that requests possess the required RBAC role.

    Intercepts the X-SecOps-Role header. For local verification and testing
    backward compatibility, missing headers default to "ANALYST".
    """

    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = [r.upper() for r in allowed_roles]

    async def __call__(
        self,
        x_secops_role: str | None = Header(default=None, alias="X-SecOps-Role")
    ) -> str:
        """Asynchronously checks user permissions from incoming header."""
        if not x_secops_role:
            # Permissive default to preserve compatibility with existing
            # dashboard endpoints while enabling structured audits.
            logger.warning("Missing X-SecOps-Role header. Defaulting request context to 'ANALYST'.")
            x_secops_role = "ANALYST"

        role = x_secops_role.upper()
        if role not in self.allowed_roles:
            logger.error(f"Security Alert: Role '{role}' attempted unauthorized access. Allowed: {self.allowed_roles}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Insufficient permissions. Role '{role}' not authorized."
            )

        return role


def require_roles(allowed_roles: List[str]):
    """Helper method to instantiate the RoleVerifier dependency."""
    return Depends(RoleVerifier(allowed_roles))
