import argparse
import json

from cyberagent.runtime import run_challenge


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberAgent CTF solver")
    parser.add_argument("challenge_id", help="challenge id from the CTF platform")
    parser.add_argument("--save", action="store_true", help="save final state to disk")
    parser.add_argument("--output-dir", default="runs", help="directory for saved run state")
    args = parser.parse_args()

    result = run_challenge(
        args.challenge_id,
        save=args.save,
        output_dir=args.output_dir,
    )

    print(json.dumps(result, ensure_ascii=False, indent=2))
