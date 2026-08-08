import os

from cyberagent.submitters.base import SubmitProvider
from cyberagent.submitters.disabled import DisabledSubmitProvider
from cyberagent.submitters.http_json import HttpJsonSubmitProvider


def get_submit_provider() -> SubmitProvider:
    provider_name = os.getenv("FLAG_SUBMIT_PROVIDER", "disabled")
    providers: dict[str, SubmitProvider] = {
        DisabledSubmitProvider.name: DisabledSubmitProvider(),
        HttpJsonSubmitProvider.name: HttpJsonSubmitProvider(),
    }

    try:
        return providers[provider_name]
    except KeyError as exc:
        supported = ", ".join(sorted(providers))
        raise ValueError(f"unsupported flag submit provider: {provider_name}; supported: {supported}") from exc
