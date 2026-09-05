from pathlib import Path
from typing import List, Optional, Set
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import os
import yaml

load_dotenv()


class ScanConfig(BaseModel):
    extensions: List[str] = Field(
        default_factory=lambda: [".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".html", ".java", ".go", ".rb", ".cs"]
    )
    max_files: int = 40
    disabled_rules: List[str] = Field(default_factory=list)
    ollama_model: Optional[str] = None
    ollama_host: Optional[str] = None


class Settings(BaseModel):
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.2")
    scan_timeout: int = int(os.getenv("SCAN_TIMEOUT", "30"))
    project_root: Path = Path(__file__).parent.parent


settings = Settings()


def load_scan_config(path: Optional[str] = None) -> ScanConfig:
    candidates = []
    if path:
        candidates.append(Path(path))
    candidates.extend([
        Path.cwd() / ".localvulnai.yml",
        Path.cwd() / ".localvulnai.yaml",
        settings.project_root / ".localvulnai.yml",
    ])

    for p in candidates:
        if p.is_file():
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            return ScanConfig(**data)
    return ScanConfig()
