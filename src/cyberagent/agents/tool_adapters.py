import base64
import binascii
import json
import re
from collections.abc import Callable
from pathlib import Path
from shlex import quote
from typing import Any, Protocol, TypedDict, runtime_checkable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from cyberagent.budget import (
    budget_allows_tool,
    budget_denied_tool_result,
    budget_exhaustion_reason,
)
from cyberagent.flag import extract_flags, merge_candidate_flags
from cyberagent.models import ChallengeState
from cyberagent.tools import ToolResult, execute_tool


class SpecialistAdapterResult(TypedDict):
    summary: str
    findings: list[dict[str, Any]]
    candidate_flags: list[str]
    tool_outputs: list[dict[str, Any]]
    next_actions: list[dict[str, Any]]


@runtime_checkable
class SpecialistToolAdapter(Protocol):
    name: str

    def describe(self) -> dict[str, Any]:
        ...

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        ...


class WebToolAdapter:
    name = "web"
    probe_paths = ("/robots.txt", "/.git/HEAD", "/admin", "/login")
    active_payloads = ("'", "{{7*7}}", "../../../../etc/passwd")
    max_form_submissions = 2
    max_parameter_probes = 6

    def __init__(
        self,
        *,
        tool_executor: Callable[..., ToolResult] = execute_tool,
    ) -> None:
        self._tool_executor = tool_executor

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Perform bounded HTTP probing, path attempts, response flag extraction, and simple form/parameter discovery.",
            "capabilities": [
                "http_get",
                "http_post",
                "path_probe",
                "flag_extract",
                "form_detect",
                "parameter_detect",
                "active_interaction",
            ],
        }

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        target = _first_remote_target(state)
        if not target:
            output = _tool_output(_missing_target_result(), caller="web_agent")
            return {
                "summary": "Web Adapter could not run because no remote target is configured.",
                "findings": [],
                "candidate_flags": [],
                "tool_outputs": [output],
                "next_actions": [{"kind": "remote_target", "reason": "missing remote target"}],
            }

        urls = _web_probe_urls(target, self.probe_paths)
        budget_state = state
        tool_outputs = []
        for url in urls:
            output = self._http_get(url, budget_state)
            tool_outputs.append(output)
            budget_state = _count_local_budget_use(budget_state, output)
        candidate_flags: list[str] = []
        findings: list[dict[str, Any]] = []
        forms: list[dict[str, Any]] = []
        parameters: list[dict[str, Any]] = []

        for output in tool_outputs:
            body = str(output.get("output", ""))
            candidate_flags = merge_candidate_flags(
                candidate_flags,
                extract_flags(body, state.get("flag_format")),
            )
            url = str(output.get("metadata", {}).get("url", ""))
            forms.extend(_detect_forms(body, url))
            parameters.extend(_detect_parameters(body, url))

        if forms:
            findings.append(
                _adapter_finding(
                    "Detected simple HTML form(s).",
                    {"forms": forms},
                )
            )
        if parameters:
            findings.append(
                _adapter_finding(
                    "Detected candidate URL parameter(s).",
                    {"parameters": parameters},
                )
            )

        cookies = _collect_cookies(tool_outputs)
        active_outputs, active_findings = self._active_interaction(
            state,
            budget_state,
            forms,
            parameters,
            tool_outputs,
            cookies,
        )
        tool_outputs.extend(active_outputs)
        findings.extend(active_findings)
        for output in active_outputs:
            candidate_flags = merge_candidate_flags(
                candidate_flags,
                extract_flags(
                    str(output.get("output", "")),
                    state.get("flag_format"),
                ),
            )

        next_actions = []
        if not candidate_flags:
            next_actions.append(
                {
                    "kind": "web_active_probe",
                    "reason": "no flag found; inspect active response differences before repeating probes",
                }
            )
        return {
            "summary": (
                f"Web Adapter probed {len(urls)} URL(s) and performed "
                f"{len(active_outputs)} active interaction(s)."
            ),
            "findings": findings,
            "candidate_flags": candidate_flags,
            "tool_outputs": tool_outputs,
            "next_actions": next_actions,
        }

    def _http_get(self, url: str, state: ChallengeState) -> dict[str, Any]:
        if not budget_allows_tool(state, "http_get"):
            return _tool_output(
                budget_denied_tool_result("http_get", budget_exhaustion_reason(state, "http_get")),
                caller="web_agent",
            )
        return _tool_output(
            self._tool_executor("http_get", {"url": url}, caller="web_agent"),
            caller="web_agent",
        )

    def _http_post(
        self,
        url: str,
        data: dict[str, str],
        state: ChallengeState,
        cookies: dict[str, str],
    ) -> dict[str, Any]:
        if not budget_allows_tool(state, "http_post"):
            return _tool_output(
                budget_denied_tool_result(
                    "http_post",
                    budget_exhaustion_reason(state, "http_post"),
                ),
                caller="web_agent",
            )
        return _tool_output(
            self._tool_executor(
                "http_post",
                {
                    "url": url,
                    "data": urlencode(data),
                    "headers": {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    "cookies": cookies,
                },
                caller="web_agent",
            ),
            caller="web_agent",
        )

    def _active_interaction(
        self,
        state: ChallengeState,
        budget_state: ChallengeState,
        forms: list[dict[str, Any]],
        parameters: list[dict[str, Any]],
        baseline_outputs: list[dict[str, Any]],
        cookies: dict[str, str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        outputs: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        submissions = 0
        probes = 0

        for form in forms:
            if submissions >= self.max_form_submissions:
                break
            method = str(form.get("method", "get")).lower()
            if method != "post":
                continue
            action = urljoin(str(form.get("page", "")), str(form.get("action", "")))
            data = _form_values(form.get("inputs", []))
            if not action or not data:
                continue
            output = self._http_post(action, data, budget_state, cookies)
            outputs.append(output)
            budget_state = _count_local_budget_use(budget_state, output)
            submissions += 1
            findings.append(
                _active_finding(
                    "Submitted a bounded form payload.",
                    target=action,
                    payload=data,
                    baseline=_baseline_for_url(baseline_outputs, str(form.get("page", ""))),
                    response=output,
                )
            )

        for parameter in parameters:
            if probes >= self.max_parameter_probes:
                break
            page = str(parameter.get("page", ""))
            href = urljoin(page, str(parameter.get("href", "")))
            for name in parameter.get("names", []):
                for payload in self.active_payloads:
                    if probes >= self.max_parameter_probes:
                        break
                    target = _with_query_value(href, str(name), payload)
                    output = self._http_get(target, budget_state)
                    outputs.append(output)
                    budget_state = _count_local_budget_use(budget_state, output)
                    probes += 1
                    baseline = _baseline_for_url(baseline_outputs, page)
                    evidence = _response_comparison(baseline, output)
                    evidence.update({"parameter": name, "payload": payload, "target": target})
                    output.setdefault("metadata", {}).update(
                        {
                            "interaction": "active",
                            "target": target,
                            "payload": {str(name): payload},
                            "judgment": evidence,
                        }
                    )
                    findings.append(
                        _adapter_finding(
                            "Active parameter probe completed.",
                            evidence,
                        )
                    )
                if probes >= self.max_parameter_probes:
                    break

        return outputs, findings


class PlaceholderToolAdapter:
    """MVP adapter contract for a domain without a real scanner."""

    def __init__(self, name: str, domain: str) -> None:
        self.name = name
        self._domain = domain

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": f"Adapter boundary for {self._domain} solving tools.",
            "capabilities": [],
        }

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        return {
            "summary": (
                f"{self._domain} Adapter received the challenge; "
                "no domain tool is configured yet."
            ),
            "findings": [],
            "candidate_flags": [],
            "tool_outputs": [],
            "next_actions": [
                {
                    "kind": "tool_adapter",
                    "reason": "domain-specific solving tools are not configured",
                }
            ],
        }


class CryptoAdapter:
    name = "crypto"
    max_encoded_candidates = 8

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": "Identify encoding layers, common RSA weaknesses, and AES mode clues from challenge text and prior tool outputs.",
            "capabilities": [
                "encoding_detect",
                "rsa_weakness_detect",
                "aes_mode_detect",
                "flag_extract",
            ],
        }

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        text = _collect_crypto_text(state)
        encoding_findings, encoding_flags = _detect_encoded_values(
            text,
            state.get("flag_format"),
            limit=self.max_encoded_candidates,
        )
        rsa_findings = _detect_rsa_weaknesses(text)
        aes_findings = _detect_aes_modes(text)
        candidate_flags = merge_candidate_flags(
            extract_flags(text, state.get("flag_format")),
            encoding_flags,
        )
        findings = [
            _crypto_finding("Detected encoded value(s).", {"encodings": encoding_findings})
        ] if encoding_findings else []
        if rsa_findings:
            findings.append(
                _crypto_finding(
                    "Detected RSA parameter weakness clue(s).",
                    {"rsa": rsa_findings},
                )
            )
        if aes_findings:
            findings.append(
                _crypto_finding(
                    "Detected AES mode clue(s).",
                    {"aes": aes_findings},
                )
            )
        analysis = {
            "encodings": encoding_findings,
            "rsa": rsa_findings,
            "aes": aes_findings,
            "candidate_flags": candidate_flags,
        }
        next_actions = _crypto_next_actions(analysis)
        return {
            "summary": _crypto_summary(analysis),
            "findings": findings,
            "candidate_flags": candidate_flags,
            "tool_outputs": [
                {
                    "caller": "crypto_agent",
                    "tool": "crypto_analysis",
                    "ok": True,
                    "output": json.dumps(analysis, ensure_ascii=False, sort_keys=True),
                    "error": None,
                    "exit_code": 0,
                    "metadata": {
                        "analysis": "crypto_static",
                        "encoding_count": len(encoding_findings),
                        "rsa_count": len(rsa_findings),
                        "aes_count": len(aes_findings),
                    },
                }
            ],
            "next_actions": next_actions,
        }


class AttachmentAnalysisAdapter:
    name = "misc"
    agent_name = "misc_agent"
    domain = "Misc"

    def __init__(
        self,
        *,
        tool_executor: Callable[..., ToolResult] = execute_tool,
    ) -> None:
        self._tool_executor = tool_executor

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                f"Analyze downloaded {self.domain} attachments with basic file, "
                "strings, and unzip listing commands."
            ),
            "capabilities": ["file", "strings", "unzip_list", "flag_extract"],
        }

    def execute(self, state: ChallengeState) -> SpecialistAdapterResult:
        attachments = [
            item
            for item in state.get("downloaded_attachments", [])
            if item.get("ok") and item.get("path")
        ]
        if not attachments:
            return {
                "summary": f"{self.domain} Adapter found no downloaded attachments to analyze.",
                "findings": [],
                "candidate_flags": [],
                "tool_outputs": [],
                "next_actions": [
                    {
                        "kind": "attachment",
                        "reason": "no downloaded attachments available",
                    }
                ],
            }

        tool_outputs: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        candidate_flags: list[str] = []
        budget_state = state
        for attachment in attachments:
            path = str(attachment["path"])
            file_output = self._run_shell(f"file -b {quote(path)}", budget_state)
            budget_state = _count_local_budget_use(budget_state, file_output)
            file_output["metadata"] = {
                **file_output.get("metadata", {}),
                "analysis": "file",
                "path": path,
            }
            tool_outputs.append(file_output)
            candidate_flags = merge_candidate_flags(
                candidate_flags,
                extract_flags(str(file_output.get("output", "")), state.get("flag_format")),
            )

            strings_output = self._run_shell(f"strings -n 4 {quote(path)} | head -200", budget_state)
            budget_state = _count_local_budget_use(budget_state, strings_output)
            strings_output["metadata"] = {
                **strings_output.get("metadata", {}),
                "analysis": "strings",
                "path": path,
            }
            tool_outputs.append(strings_output)
            candidate_flags = merge_candidate_flags(
                candidate_flags,
                extract_flags(str(strings_output.get("output", "")), state.get("flag_format")),
            )

            if _looks_like_zip(path, file_output.get("output", "")):
                unzip_output = self._run_shell(f"unzip -l {quote(path)}", budget_state)
                budget_state = _count_local_budget_use(budget_state, unzip_output)
                unzip_output["metadata"] = {
                    **unzip_output.get("metadata", {}),
                    "analysis": "unzip_list",
                    "path": path,
                }
                tool_outputs.append(unzip_output)
                candidate_flags = merge_candidate_flags(
                    candidate_flags,
                    extract_flags(str(unzip_output.get("output", "")), state.get("flag_format")),
                )

            findings.append(
                {
                    "kind": "finding",
                    "agent": self.agent_name,
                    "summary": f"Analyzed attachment {Path(path).name}.",
                    "evidence": {
                        "path": path,
                        "file_type": file_output.get("output", "").strip(),
                    },
                }
            )

        return {
            "summary": f"{self.domain} Adapter analyzed {len(attachments)} downloaded attachment(s).",
            "findings": findings,
            "candidate_flags": candidate_flags,
            "tool_outputs": tool_outputs,
            "next_actions": [],
        }

    def _run_shell(self, command: str, state: ChallengeState) -> dict[str, Any]:
        if not budget_allows_tool(state, "shell"):
            return _tool_output(
                budget_denied_tool_result("shell", budget_exhaustion_reason(state, "shell")),
                caller=self.agent_name,
            )
        return _tool_output(
            self._tool_executor("shell", {"command": command}, caller=self.agent_name),
            caller=self.agent_name,
        )


class ForensicsAdapter(AttachmentAnalysisAdapter):
    name = "forensics"
    agent_name = "forensics_agent"
    domain = "Forensics"


class SpecialistToolAdapterRegistry:
    def __init__(self, adapters: list[SpecialistToolAdapter] | None = None) -> None:
        self._adapters: dict[str, SpecialistToolAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: SpecialistToolAdapter) -> None:
        if adapter.name in self._adapters:
            raise ValueError(f"specialist adapter already registered: {adapter.name}")
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> SpecialistToolAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise KeyError(f"unknown specialist adapter: {name}") from exc

    def describe_all(self) -> list[dict[str, Any]]:
        return [adapter.describe() for adapter in self._adapters.values()]


def build_default_specialist_adapters(
    *,
    tool_executor: Callable[..., ToolResult] = execute_tool,
) -> SpecialistToolAdapterRegistry:
    return SpecialistToolAdapterRegistry(
        [
            WebToolAdapter(tool_executor=tool_executor),
            CryptoAdapter(),
            AttachmentAnalysisAdapter(tool_executor=tool_executor),
            ForensicsAdapter(tool_executor=tool_executor),
        ]
    )


def _first_remote_target(state: ChallengeState) -> str:
    for target in state.get("remote_targets", []):
        if isinstance(target, str) and target.strip():
            return target.strip()
    return ""


def _missing_target_result() -> ToolResult:
    return {
        "tool": "http_get",
        "ok": False,
        "output": "",
        "error": "missing remote target",
        "exit_code": None,
        "metadata": {"url": ""},
    }


def _tool_output(result: ToolResult, *, caller: str) -> dict[str, Any]:
    return {
        "caller": caller,
        "tool": result["tool"],
        "ok": result["ok"],
        "output": result["output"],
        "error": result["error"],
        "exit_code": result["exit_code"],
        "metadata": result.get("metadata", {}),
    }


def _looks_like_zip(path: str, file_output: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix == ".zip" or "zip archive" in file_output.lower()


def _collect_crypto_text(state: ChallengeState) -> str:
    parts = [
        state.get("title", ""),
        state.get("description", ""),
        state.get("category_hint", ""),
        state.get("flag_format", ""),
        state.get("specialist_skill_context", ""),
        json.dumps(state.get("raw_challenge", {}), ensure_ascii=False),
        " ".join(state.get("attachments", [])),
    ]
    for output in state.get("tool_outputs", []):
        parts.append(str(output.get("output", "")))
        parts.append(json.dumps(output.get("metadata", {}), ensure_ascii=False))
    for finding in state.get("findings", []):
        parts.append(str(finding.get("summary", "")))
        parts.append(json.dumps(finding.get("evidence", {}), ensure_ascii=False))
    return "\n".join(part for part in parts if part)


def _detect_encoded_values(
    text: str,
    flag_format: str | None,
    *,
    limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    flags: list[str] = []
    seen: set[tuple[str, str]] = set()
    for kind, value in _encoded_candidates(text):
        key = (kind, value)
        if key in seen:
            continue
        seen.add(key)
        decoded = _decode_candidate(kind, value)
        if decoded is None or not _is_useful_decoding(decoded):
            continue
        decoded_flags = extract_flags(decoded, flag_format)
        flags = merge_candidate_flags(flags, decoded_flags)
        findings.append(
            {
                "encoding": kind,
                "value": value[:120],
                "decoded_preview": decoded[:160],
                "decoded_flags": decoded_flags,
            }
        )
        if len(findings) >= limit:
            break
    return findings, flags


def _encoded_candidates(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for match in re.finditer(r"\b(?:0x)?[0-9a-fA-F]{16,}\b", text):
        value = match.group(0)
        if value.startswith(("0x", "0X")):
            value = value[2:]
        if len(value) % 2 == 0:
            candidates.append(("hex", value))
    for match in re.finditer(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", text):
        value = match.group(0)
        if len(value) % 4 == 0 and not re.fullmatch(r"[0-9a-fA-F]+", value):
            candidates.append(("base64", value))
    return candidates


def _decode_candidate(kind: str, value: str) -> str | None:
    try:
        if kind == "hex":
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        if kind == "base64":
            return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return None
    return None


def _is_useful_decoding(value: str) -> bool:
    if not value.strip():
        return False
    printable = sum(1 for char in value if char.isprintable() or char in "\r\n\t")
    return printable / max(len(value), 1) >= 0.85


def _detect_rsa_weaknesses(text: str) -> list[dict[str, Any]]:
    values = _extract_named_ints(text, names=("n", "e", "c", "p", "q", "d"))
    findings: list[dict[str, Any]] = []
    if "p" in values and "q" in values:
        findings.append(
            {
                "kind": "factor_provided",
                "reason": "both p and q appear in challenge material",
                "parameters": sorted({"p", "q", *values.keys()}),
            }
        )
    for e in values.get("e", []):
        if e in {3, 5, 17}:
            findings.append(
                {
                    "kind": "small_public_exponent",
                    "reason": f"e={e} may allow low-exponent attacks without padding",
                    "e": e,
                }
            )
        if e == 1:
            findings.append(
                {
                    "kind": "invalid_public_exponent",
                    "reason": "e=1 means ciphertext can directly expose plaintext",
                    "e": e,
                }
            )
    if "n" in values and "e" in values and "c" in values:
        findings.append(
            {
                "kind": "standard_rsa_tuple",
                "reason": "n/e/c tuple detected; try factoring n, low exponent, or padding weakness",
                "parameters": ["n", "e", "c"],
            }
        )
    lowered = text.lower()
    if any(token in lowered for token in ("rsa", "public key", "modulus", "ciphertext")):
        if not findings:
            findings.append(
                {
                    "kind": "rsa_clue",
                    "reason": "RSA-related vocabulary detected but parameters are incomplete",
                    "parameters": sorted(values),
                }
            )
    return findings


def _extract_named_ints(text: str, *, names: tuple[str, ...]) -> dict[str, list[int]]:
    values: dict[str, list[int]] = {}
    names_pattern = "|".join(re.escape(name) for name in names)
    pattern = re.compile(
        rf"\b(?P<name>{names_pattern})\b\s*(?:=|:)\s*(?P<value>0x[0-9a-fA-F]+|\d+)",
        flags=re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        name = match.group("name").lower()
        raw = match.group("value")
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        values.setdefault(name, [])
        if value not in values[name]:
            values[name].append(value)
    return values


def _detect_aes_modes(text: str) -> list[dict[str, Any]]:
    lowered = text.lower()
    if "aes" not in lowered and not any(mode in lowered for mode in ("ecb", "cbc", "ctr", "gcm")):
        return []
    findings: list[dict[str, Any]] = []
    for mode in ("ecb", "cbc", "ctr", "gcm", "cfb", "ofb"):
        if re.search(rf"\b{mode}\b", lowered):
            findings.append(
                {
                    "kind": "mode_keyword",
                    "mode": mode.upper(),
                    "reason": f"{mode.upper()} mode keyword appears in challenge material",
                }
            )
    repeated_blocks = _detect_repeated_cipher_blocks(text)
    if repeated_blocks:
        findings.append(
            {
                "kind": "repeated_cipher_blocks",
                "mode": "ECB",
                "reason": "repeated 16-byte ciphertext blocks suggest ECB or repeated plaintext structure",
                "samples": repeated_blocks,
            }
        )
    if "cbc" in lowered and "iv" not in lowered:
        findings.append(
            {
                "kind": "missing_iv_clue",
                "mode": "CBC",
                "reason": "CBC is mentioned but no IV clue was found",
            }
        )
    return findings


def _detect_repeated_cipher_blocks(text: str) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for kind, value in _encoded_candidates(text):
        data = _decode_bytes(kind, value)
        if data is None or len(data) < 32:
            continue
        blocks = [data[index : index + 16] for index in range(0, len(data), 16)]
        counts = {
            block: blocks.count(block)
            for block in set(blocks)
            if len(block) == 16 and blocks.count(block) > 1
        }
        if counts:
            samples.append(
                {
                    "encoding": kind,
                    "value": value[:120],
                    "repeated_blocks": len(counts),
                }
            )
    return samples[:3]


def _decode_bytes(kind: str, value: str) -> bytes | None:
    try:
        if kind == "hex":
            return bytes.fromhex(value)
        if kind == "base64":
            return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    return None


def _crypto_next_actions(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if analysis["candidate_flags"]:
        return actions
    if analysis["rsa"]:
        actions.append(
            {
                "kind": "crypto_rsa_attack",
                "reason": "RSA parameters or weakness clues detected; try factoring/low-exponent/padding attack next",
            }
        )
    if analysis["aes"]:
        actions.append(
            {
                "kind": "crypto_aes_analysis",
                "reason": "AES mode clues detected; verify mode assumptions, IV handling, and block structure",
            }
        )
    if analysis["encodings"]:
        actions.append(
            {
                "kind": "crypto_decode_chain",
                "reason": "encoded values decoded to printable data but no flag was confirmed",
            }
        )
    if not actions:
        actions.append(
            {
                "kind": "crypto_more_evidence",
                "reason": "no strong crypto primitive or encoding clue was found",
            }
        )
    return actions


def _crypto_summary(analysis: dict[str, Any]) -> str:
    return (
        "Crypto Adapter analyzed static challenge material: "
        f"{len(analysis['encodings'])} encoding clue(s), "
        f"{len(analysis['rsa'])} RSA clue(s), "
        f"{len(analysis['aes'])} AES clue(s), "
        f"{len(analysis['candidate_flags'])} candidate flag(s)."
    )


def _crypto_finding(summary: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "finding",
        "agent": "crypto_agent",
        "summary": summary,
        "evidence": evidence,
    }


def _count_local_budget_use(state: ChallengeState, output: dict[str, Any]) -> ChallengeState:
    usage = dict(state.get("budget_usage", {}))
    tool = output.get("tool", "")
    if output.get("metadata", {}).get("budget_denied"):
        return state
    usage["tool_calls"] = usage.get("tool_calls", 0) + 1
    if tool.startswith("http_"):
        usage["http_requests"] = usage.get("http_requests", 0) + 1
    if tool == "shell":
        usage["shell_commands"] = usage.get("shell_commands", 0) + 1
    return {**state, "budget_usage": usage}


def _web_probe_urls(target: str, paths: tuple[str, ...]) -> list[str]:
    urls = [target]
    for path in paths:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        if url not in urls:
            urls.append(url)
    return urls


def _detect_forms(body: str, page_url: str) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for match in re.finditer(r"<form\b(?P<attrs>[^>]*)>", body, flags=re.IGNORECASE):
        attrs = match.group("attrs")
        forms.append(
            {
                "page": page_url,
                "method": _html_attr(attrs, "method") or "get",
                "action": _html_attr(attrs, "action") or page_url,
                "inputs": _nearby_inputs(body, match.end()),
            }
        )
    return forms


def _nearby_inputs(body: str, start: int) -> list[str]:
    end = body.find("</form>", start)
    fragment = body[start : end if end != -1 else start + 2000]
    names = [
        match.group(1)
        for match in re.finditer(
            r"<input\b[^>]*\bname=[\"']?([^\"'\s>]+)",
            fragment,
            flags=re.IGNORECASE,
        )
    ]
    return list(dict.fromkeys(names))


def _detect_parameters(body: str, page_url: str) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for href in re.findall(r"\bhref=[\"']([^\"']+\?[^\"']+)[\"']", body, flags=re.IGNORECASE):
        query = href.split("?", 1)[1].split("#", 1)[0]
        names = [
            item.split("=", 1)[0]
            for item in query.split("&")
            if item and item.split("=", 1)[0]
        ]
        if names:
            parameters.append(
                {
                    "page": page_url,
                    "href": href,
                    "names": list(dict.fromkeys(names)),
                }
            )
    return parameters


def _form_values(inputs: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for name in inputs:
        lowered = name.lower()
        if "pass" in lowered:
            value = "admin"
        elif any(token in lowered for token in ("user", "email", "login", "name")):
            value = "admin"
        elif any(token in lowered for token in ("search", "query", "keyword", "q")):
            value = "test"
        else:
            value = "test"
        values[name] = value
    return values


def _with_query_value(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for key, current in query:
        if key == name:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, current))
    if not replaced:
        updated.append((name, value))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(updated), parsed.fragment)
    )


def _collect_cookies(outputs: list[dict[str, Any]]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for output in outputs:
        set_cookies = output.get("metadata", {}).get("set_cookies", {})
        if isinstance(set_cookies, dict):
            cookies.update(
                {str(name): str(value) for name, value in set_cookies.items()}
            )
    return cookies


def _baseline_for_url(
    outputs: list[dict[str, Any]],
    url: str,
) -> dict[str, Any]:
    for output in outputs:
        metadata = output.get("metadata", {})
        if metadata.get("url") == url:
            return output
    return {}


def _response_comparison(
    baseline: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, Any]:
    baseline_metadata = baseline.get("metadata", {})
    response_metadata = response.get("metadata", {})
    baseline_body = str(baseline.get("output", ""))
    response_body = str(response.get("output", ""))
    indicators: list[str] = []
    lowered = response_body.lower()
    if any(
        marker in lowered
        for marker in (
            "sql syntax",
            "mysql",
            "sqlite",
            "postgres",
            "odbc",
            "syntax error",
        )
    ):
        indicators.append("sql_error")
    if "49" in response_body and "{{7*7}}" not in baseline_body:
        indicators.append("ssti_evaluation")
    if "root:x:" in response_body:
        indicators.append("lfi_passwd")
    status_changed = (
        baseline_metadata.get("status") is not None
        and response_metadata.get("status") is not None
        and baseline_metadata.get("status") != response_metadata.get("status")
    )
    length_changed = len(baseline_body) != len(response_body)
    return {
        "baseline_status": baseline_metadata.get("status"),
        "response_status": response_metadata.get("status"),
        "status_changed": status_changed,
        "baseline_length": len(baseline_body),
        "response_length": len(response_body),
        "length_delta": len(response_body) - len(baseline_body),
        "length_changed": length_changed,
        "indicators": indicators,
        "interesting": bool(indicators or status_changed),
    }


def _active_finding(
    summary: str,
    *,
    target: str,
    payload: dict[str, str],
    baseline: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, Any]:
    evidence = _response_comparison(baseline, response)
    evidence.update({"target": target, "payload": payload})
    response.setdefault("metadata", {}).update(
        {
            "interaction": "active",
            "target": target,
            "payload": payload,
            "judgment": evidence,
        }
    )
    return _adapter_finding(summary, evidence)


def _html_attr(attrs: str, name: str) -> str:
    match = re.search(
        rf"\b{name}=[\"']?([^\"'\s>]+)",
        attrs,
        flags=re.IGNORECASE,
    )
    return match.group(1).lower() if match else ""


def _adapter_finding(summary: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "finding",
        "agent": "web_agent",
        "summary": summary,
        "evidence": evidence,
    }
