from typing import Literal
from uuid import UUID, uuid4
from beanie import Document
from pydantic import ConfigDict, Field

class UUIDDocument(Document):
    id: UUID = Field(default_factory=uuid4, alias="_id") # type: ignore

    model_config = ConfigDict(populate_by_name=True)

    @property
    def document_id(self) -> UUID:
        return self.id


EntityType = Literal["user", "service", "device", "unknown"]
