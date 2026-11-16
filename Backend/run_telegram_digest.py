"""
GroundedCVE Weekly Telegram Digest.
Posts one header message for the week, then one short message per incident,
each linking to that incident's reader page (BASE_URL/incident/<Item_ID>).

Needs TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env (see .env.example).

  python Backend/run_telegram_digest.py --dry-run     # print the messages, send nothing
  python Backend/run_telegram_digest.py               # preview, then ask before sending
  python Backend/run_telegram_digest.py --yes         # send without asking (scheduled runs)

Each digest's header says "Edition <week>" and is pinned in the channel. If this
week's edition is already pinned (e.g. a teammate's PC sent it), nothing is sent.
Use --force to send anyway.
"""
import argparse
from pathlib import Path
import random
import sys
import time

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.api.data_service import data_service
from Backend.api.novelty import NoveltyChecker, PublishedIndex, similarity_threshold
from Backend.api.telegram_service import (
    base_url, bot_token, compose_digest, edition_label, pinned_edition, select_digest_items, telegram_service,
)


def make_novelty_checker() -> NoveltyChecker:
    """Ledger of sent items, plus the Qdrant published collection when Qdrant and Ollama answer."""
    index = None
    try:
        import os
        from Backend.storage.embedder import OllamaEmbedder
        from Backend.storage.vector_db import get_client

        client = get_client()
        client.info()
        threshold = similarity_threshold(os.getenv("NOVELTY_SIMILARITY"))
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
    parser.add_argument("--force", action="store_true",
                        help="Send even if this week's edition is already pinned in the channel")
    parser.add_argument("--jitter", type=int, default=0,
                        help="Wait a random 0-N seconds before checking the channel, so PCs scheduled "
                             "at the same time don't both post")
    args = parser.parse_args()

    # Windows consoles default to a code page that can't print the emoji in the messages
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    chat_id = args.chat_id or telegram_service.chat_id()
    edition = edition_label()

    if bot_token() and chat_id and not args.force:
        if args.jitter > 0 and not args.dry_run:
            wait = random.uniform(0, args.jitter)
            print(f"Waiting {wait:.0f}s before checking the channel...")
            time.sleep(wait)
        check = pinned_edition(bot_token(), chat_id)
        if not check["ok"]:
            print(f"Could not read the channel's pinned message ({check['error']}); continuing without that check.")
        elif check["edition"] == edition:
            print(f"Edition {edition} is already pinned in the channel, so this week's digest was already posted. "
                  "No update. (Use --force to send anyway.)")
            return

    novelty = None if args.include_sent else make_novelty_checker()
    items = select_digest_items(data_service.get_all_candidates(), days=args.days, top_n=args.top, novelty=novelty)
    messages = compose_digest(items, args.days, edition=edition)

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

    result = telegram_service.send_digest(messages, chat_id=chat_id, pin=True)
    # messages[0] is the header; remember every incident that actually went out
    sent_items = items[: max(0, result["sent"] - 1)]
    if sent_items:
        (novelty or NoveltyChecker()).record(sent_items)
        print(f"Recorded {len(sent_items)} sent incidents so later digests don't repeat them.")
    if result["error"]:
        sys.exit(f"Sent {result['sent']}/{result['total']} messages, then stopped: {result['error']}")
    print(f"Sent {result['sent']}/{result['total']} messages to chat {chat_id}.")
    if result.get("pinned"):
        print(f"Pinned the header as edition {edition}, so other PCs skip this week.")
    else:
        print(f"Could not pin the header ({result.get('pin_error')}). Give the bot the 'Pin Messages' "
              "admin right, otherwise other PCs can't tell this week was already posted.")


if __name__ == "__main__":
    main()
