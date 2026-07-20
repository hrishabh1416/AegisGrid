"""AegisGrid Router sub-package.

Exposes the ``telemetry_router`` and ``containment_router`` for mounting
in the main FastAPI application.
"""

from app.routers.telemetry import router as telemetry_router  # noqa: F401
from app.routers.containment import router as containment_router  # noqa: F401
