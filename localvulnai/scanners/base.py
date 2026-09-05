from abc import ABC, abstractmethod
from typing import List
from localvulnai.models.finding import Finding


class BaseScanner(ABC):
    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run the scan and return a list of findings."""
        pass
