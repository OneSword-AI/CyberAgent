import os

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI


def get_llm() -> BaseChatModel:
    """Create the default chat model used by agent nodes."""
    _require_env("OPENAI_API_KEY")

    return ChatOpenAI(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        base_url=os.getenv("OPENAI_BASE_URL"),
        temperature=_float_env("OPENAI_TEMPERATURE", 0),
        timeout=_float_env("OPENAI_TIMEOUT", 60),
        max_retries=_int_env("OPENAI_MAX_RETRIES", 2),
    )


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is required to initialize the LLM client")
    return value


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    return default if value is None else float(value)


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    return default if value is None else int(value)
