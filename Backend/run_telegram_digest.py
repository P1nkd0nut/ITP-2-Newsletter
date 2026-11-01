"""
GroundedCVE Weekly Telegram Digest.
Posts one header message for the week, then one short message per incident,
each linking to that incident's reader page (BASE_URL/incident/<Item_ID>).

Needs TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env (see .env.example).

  python Backend/run_telegram_digest.py --dry-run     # print the messages, send nothing
  python Backend/run_telegram_digest.py               # preview, then ask before sending
  python Backend/run_telegram_digest.py --yes         # send without asking (scheduled runs)
"""
import argparse
from pathlib import Path
import sys

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.api.data_service import data_service
from Backend.api.novelty import DEFAULT_SIMILARITY, NoveltyChecker, PublishedIndex
from Backend.api.telegram_service import base_url, bot_token, compose_digest, select_digest_items, telegram_service


def make_novelty_checker() -> NoveltyChecker:
    """Ledger of sent items, plus the Qdrant published collection when Qdrant and Ollama answer."""
    index = None
    try:
        import os
        from Backend.storage.embedder import OllamaEmbedder
        from Backend.storage.vector_db import get_client

        client = get_client()
        client.info()
        threshold = float(os.getenv("NOVELTY_SIMILARITY", DEFAULT_SIMILARITY))
        index = PublishedIndex(client, OllamaEmbedder(), threshold=threshold)
    except Exception as e:
        print(f"Qdrant not reachable ({e.__class__.__name__}); novelty check uses the sent-items ledger only")
    return NoveltyChecker(index=index)


def main():
    parser = argparse.ArgumentParser(
        description="Send the weekly GroundedCVE digest to Telegram",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--days", type=int, default=7, help="Include incidents published in the last N days")
    parser.add_argument("--top", type=int, default=10, help="Maximum number of incidents to post")
    parser.add_argument("--chat-id", help="Override TELEGRAM_CHAT_ID for this run")
    parser.add_argument("--dry-run", action="store_true", help="Print the messages without sending")
    parser.add_argument("-y", "--yes", action="store_true", help="Send without asking for approval")
    parser.add_argument("--include-sent", action="store_true",
                        help="Also include items sent in earlier digests that have nothing new")
    args = parser.parse_args()

    # Windows consoles default to a code page that can't print the emoji in the messages
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    novelty = None if args.include_sent else make_novelty_checker()
    items = select_digest_items(data_service.get_all_candidates(), days=args.days, top_n=args.top, novelty=novelty)
    messages = compose_digest(items, args.days)
    chat_id = args.chat_id or telegram_service.chat_id()

    for i, text in enumerate(messages, 1):
        print(f"----- Message {i}/{len(messages)} ({len(text)} chars) -----")
        print(text)
        print()

    print(f"Links point to: {base_url()}")
    if args.dry_run:
        print(f"Dry run: {len(messages)} messages built, nothing sent.")
        return

    if not bot_token():
        sys.exit("TELEGRAM_BOT_TOKEN is not set in .env. Nothing sent.")
    if not chat_id:
        sys.exit("No chat id: set TELEGRAM_CHAT_ID in .env or pass --chat-id. Nothing sent.")

    if not args.yes:
        answer = input(f"Send these {len(messages)} messages to chat {chat_id}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Cancelled. Nothing sent.")
            return

    result = telegram_service.send_digest(messages, chat_id=chat_id)
    # messages[0] is the header; remember every incident that actually went out
    sent_items = items[: max(0, result["sent"] - 1)]
    if sent_items:
        (novelty or NoveltyChecker()).record(sent_items)
        print(f"Recorded {len(sent_items)} sent incidents so later digests don't repeat them.")
    if result["error"]:
        sys.exit(f"Sent {result['sent']}/{result['total']} messages, then stopped: {result['error']}")
    print(f"Sent {result['sent']}/{result['total']} messages to chat {chat_id}.")


if __name__ == "__main__":
    main()
