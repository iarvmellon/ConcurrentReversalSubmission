"""Close every pending sale sequentially."""
from datetime import datetime
import json
import socket
import time
from typing import Optional

from main import INITIAL_SEQUENCE_NUMBER, INITIAL_TRANSMISSION_NUMBER
from send_packets import (
    STATE_FILE,
    remove_pending_sale,
    reserve_message_numbers,
    send_close_batch,
)

HOST = "10.1.110.84"
PORT = 28420
TIMEOUT = 5.0
DEFAULT_TID = "00000006"
AMOUNT = "0001"
DELAY_SECONDS = 1.0


def remove_closed_sale(sequence_number: str, tid: Optional[str]) -> None:
    """Remove exactly one successfully closed SALE from the shared history."""
    remove_pending_sale(STATE_FILE, sequence_number, tid)


def close_pending_sales(sales: list[dict]) -> tuple[int, int]:
    """Close all pending batches one after another."""
    closed = 0
    for index, sale in enumerate(sales):
        stored_tid = sale.get("tid")
        tid = stored_tid or DEFAULT_TID
        sale_sequence = sale["sequence_number"]
        close_sequence, transmission = reserve_message_numbers(
            STATE_FILE,
            INITIAL_SEQUENCE_NUMBER,
            INITIAL_TRANSMISSION_NUMBER,
            record=False,
            tid=tid,
        )
        close_sequence = (
            f"{close_sequence[:3]}{sale_sequence[3:6]}{close_sequence[6:]}"
        )
        sale_count = int(sale.get("approved") is True)
        print(
            f"TID={tid} closing batch=1{sale_sequence[3:6]} "
            f"rcncltPrdId={sale_sequence[6:9]} "
            f"transmission={transmission} amount={sale_count * int(AMOUNT)}",
            flush=True,
        )
        try:
            success = send_close_batch(
                HOST,
                PORT,
                TIMEOUT,
                transmission,
                close_sequence,
                sale_count,
                tid,
                AMOUNT,
            )
            if success:
                remove_closed_sale(sale_sequence, stored_tid)
                closed += 1
        except socket.timeout:
            print(f"TID={tid} batch=1{sale_sequence[3:6]}: timeout", flush=True)
        except OSError as exc:
            print(
                f"TID={tid} batch=1{sale_sequence[3:6]}: socket error: {exc}",
                flush=True,
            )
        if index != len(sales) - 1:
            time.sleep(DELAY_SECONDS)
    return closed, len(sales) - closed


def main() -> None:
    print(f"Close start time: {datetime.now().isoformat(timespec='seconds')}", flush=True)
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    history = state if isinstance(state, list) else state.get("history", [])
    if not history:
        print("No pending sales found", flush=True)
        return

    print(
        f"Closing {len(history)} pending batches sequentially",
        flush=True,
    )
    close_started_at = time.perf_counter()
    closed, remaining = close_pending_sales(history)
    close_elapsed = time.perf_counter() - close_started_at

    print(
        f"Close completed: closed={closed}, remaining={remaining}, "
        f"elapsed={close_elapsed:.2f} seconds",
        flush=True,
    )


if __name__ == "__main__":
    main()
