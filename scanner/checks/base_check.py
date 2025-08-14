from abc import ABC, abstractmethod
from typing import List, Callable, Optional
from scanner.vulnerability import Finding
from crawler import PageData
from http_client import HTTPClient

class BaseCheck(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    def scan(self, http: HTTPClient, page: PageData, *, status_cb: Optional[Callable[[str], None]] = None, config=None) -> List[Finding]:
        raise NotImplementedError

