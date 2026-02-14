from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime


class ClientBase(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    role: str = Field(default="agent", max_length=20)
    scopes: str | None = None


class ClientCreate(ClientBase):
    pass


class ClientResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_id: str
    name: str
    role: str
    scopes: str | None
    is_active: bool
    created_at: datetime


class ClientCreateResponse(ClientResponse):
    client_secret: str


class ClientCredentialsRequest(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str


class ClientTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
