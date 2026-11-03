"""Stable response contracts used by high-traffic report APIs."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PageResponse(BaseModel):
    items: List[Any] = Field(default_factory=list)
    total: int = 0
    offset: int = 0
    limit: int = 0
    has_next: bool = False
    file: str = ""
    section: Optional[str] = None

    class Config:
        extra = "allow"


class ProcessDetailResponse(BaseModel):
    ok: bool = True
    file: str
    pid: int
    item: Dict[str, Any]


class SectionsResponse(BaseModel):
    file: str
    sections: Dict[str, Any] = Field(default_factory=dict)


class FileTreeResponse(BaseModel):
    files: List[Dict[str, Any]] = Field(default_factory=list)
    tree: List[Dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    filtered_total: int = 0
    returned: int = 0
    offset: int = 0
    limit: int = 0
    has_next: bool = False
    truncated: bool = False
    root: str = ""

    class Config:
        extra = "allow"


class DirectoryPageResponse(BaseModel):
    items: List[Dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    offset: int = 0
    limit: int = 0
    has_next: bool = False
    path: str = ""
    file: str = ""

    class Config:
        extra = "allow"
