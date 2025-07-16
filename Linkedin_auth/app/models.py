from typing import Optional

from sqlmodel import SQLModel, Field, UniqueConstraint


class User(SQLModel, table=True):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_username"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, nullable=False)
    hashed_password: str

    # LinkedIn fields
    linkedin_id: Optional[str] = Field(default=None, index=True)
    linkedin_access_token: Optional[str] = None
    linkedin_verified: bool = Field(default=False, nullable=False)
