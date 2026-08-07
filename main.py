"""Configurable sales runner."""
import fcntl
import time
from pathlib import Path

from send_packets import (
    STATE_FILE,
    reserve_sale_run,
    send_close_batch,
    send_timeout_reversal,
    send_sales_in_order,
)
INITIAL_SEQUENCE_NUMBER = "0015304720"

HOST = "10.1.110.84"
PORT = 28420
TIMEOUT = 5.0
TIDS = ["00003971"]
AMOUNT = "0001"
SALES_PER_RUN = 4
REVERSAL_DELAY_SECONDS = 3.0
CLOSE_BATCH_DELAY_SECONDS = 1.0
EXPERIMENT_DELAY_SECONDS = 0.01
STATE = Path(STATE_FILE)
RUN_LOCK = STATE.with_name("sales_run.lock")


def run_sales():
    tid = TIDS[0]
    sales = reserve_sale_run(
        STATE,
        INITIAL_SEQUENCE_NUMBER,
        tid,
        sale_count=SALES_PER_RUN,
    )
    responses = send_sales_in_order(
        HOST,
        PORT,
        TIMEOUT,
        sales,
        tid,
        AMOUNT,
        experiment_delay=EXPERIMENT_DELAY_SECONDS,
    )
    for sale_number, sale_response in enumerate(responses, 1):
        sale_approved = sale_response.get("response_code") in {"000", "001"}
        print(
            f"SALE {sale_number}/{SALES_PER_RUN} approved={sale_approved}",
            flush=True,
        )
    print(
        f"SALE {SALES_PER_RUN}/{SALES_PER_RUN} sent without waiting for response",
        flush=True,
    )
    fourth_sequence, _ = sales[-1]
    reversal_sequence = fourth_sequence
    print(
        f"Waiting {REVERSAL_DELAY_SECONDS}s before the fourth SALE REVERSAL",
        flush=True,
    )
    time.sleep(REVERSAL_DELAY_SECONDS)
    reversal_response = send_timeout_reversal(
        HOST,
        PORT,
        TIMEOUT,
        fourth_sequence,
        reversal_sequence,
        "00",
        tid,
        AMOUNT,
    )
    reversal_approved = reversal_response.get("response_code") in {"000", "001"}
    print(f"REVERSAL approved={reversal_approved}", flush=True)

    print(
        f"Waiting {CLOSE_BATCH_DELAY_SECONDS}s after the REVERSAL response "
        "before CLOSE BATCH",
        flush=True,
    )
    time.sleep(CLOSE_BATCH_DELAY_SECONDS)

    approved_sale_count = sum(
        response.get("response_code") in {"000", "001"}
        for response in responses
    )
    close_approved = send_close_batch(
        HOST,
        PORT,
        TIMEOUT,
        "00",
        fourth_sequence,
        approved_sale_count,
        tid,
        AMOUNT,
    )
    print(f"CLOSE BATCH approved={close_approved}", flush=True)


def main():
    RUN_LOCK.touch(exist_ok=True)
    with RUN_LOCK.open("r+") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(
                "Another SALE run is already active; this run was not started"
            ) from None
        try:
            run_sales()
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


if __name__ == "__main__":
    main()
