import argparse
import json

from dotenv import load_dotenv

from cyberagent.graph import build_graph, initial_state


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description="CyberAgent CTF solver")
    parser.add_argument("challenge_id", help="challenge id from the CTF platform")
    args = parser.parse_args()

    app = build_graph()
    result = app.invoke(initial_state(args.challenge_id))

    print(json.dumps(result, ensure_ascii=False, indent=2))
