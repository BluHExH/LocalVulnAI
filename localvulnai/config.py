from pathlib import Path
from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseModel):
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.2")
    scan_timeout: int = int(os.getenv("SCAN_TIMEOUT", "30"))
    project_root: Path = Path(__file__).parent.parent


settings = Settings()
