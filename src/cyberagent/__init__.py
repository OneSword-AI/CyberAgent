import argparse
import json

from cyberagent.runtime import run_challenge


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberAgent CTF solver")
    parser.add_argument("challenge_id", help="challenge id from the CTF platform")
    args = parser.parse_args()

    result = run_challenge(args.challenge_id)

    print(json.dumps(result, ensure_ascii=False, indent=2))
