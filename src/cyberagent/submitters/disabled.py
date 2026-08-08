from cyberagent.submitters.base import SubmitResult


class DisabledSubmitProvider:
    name = "disabled"

    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        return {
            "submitted": False,
            "accepted": None,
            "status": "disabled",
            "message": "remote flag submission is disabled",
            "raw_response": None,
        }
