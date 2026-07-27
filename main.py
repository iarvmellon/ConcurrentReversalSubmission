"""Configurable sales runner."""
from pathlib import Path

from send_packets import (
    STATE_FILE,
    send_packets,
)
INITIAL_SEQUENCE_NUMBER = "0015304720"
INITIAL_TRANSMISSION_NUMBER = "70"

HOST = "10.1.110.84"
PORT = 28420
TIMEOUT = 5.0
TIDS = ["00003971"]
AMOUNT = "0001"
TRANSACTION_COUNT = 30
INCREMENT_BATCH_PER_SALE = True
STATE = Path(STATE_FILE)


def send_sales(host, port, timeout, count, tid, amount, delay=0.0,
               increment_batch_per_sale=False):
    """Send sales serially, waiting *delay* seconds between requests."""
    return send_packets(host, port, timeout, state_file=STATE, nof_trx=count,
                        tid=tid, amount=amount, delay_seconds=delay,
                        send_close_batches=False,
                        increment_batch_per_sale=increment_batch_per_sale,
                        initial_sequence_number=INITIAL_SEQUENCE_NUMBER,
                        initial_transmission_number=INITIAL_TRANSMISSION_NUMBER)


def main():
    print(
        f"Sending {TRANSACTION_COUNT} sales sequentially for each of "
        f"{len(TIDS)} TIDs ({len(TIDS) * TRANSACTION_COUNT} total)",
        flush=True,
    )
    for tid in TIDS:
        send_sales(
            HOST,
            PORT,
            TIMEOUT,
            TRANSACTION_COUNT,
            tid,
            AMOUNT,
            delay=0.1,
            increment_batch_per_sale=INCREMENT_BATCH_PER_SALE,
        )


if __name__ == "__main__":
    main()
