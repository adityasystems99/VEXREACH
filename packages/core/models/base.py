"""Base Pydantic model with strict validation settings."""

from pydantic import BaseModel, ConfigDict


class VEXReachBaseModel(BaseModel):
    """Base class for all domain models, enforcing strict typing and immutability where desired."""

    model_config = ConfigDict(
        strict=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="forbid",
    )
