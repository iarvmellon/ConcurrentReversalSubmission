"""Configurable sales runner."""
import fcntl
from pathlib import Path

from send_packets import (
    STATE_FILE,
    reserve_sale_run,
    send_sales_in_order,
)
INITIAL_SEQUENCE_NUMBER = "0015304720"

HOST = "10.1.110.84"
PORT = 28420
TIMEOUT = 5.0
TIDS = ["00003971"]
AMOUNT = "0001"
SALES_PER_RUN = 3
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
    responses = send_sales_in_order(HOST, PORT, TIMEOUT, sales, tid, AMOUNT)
    for sale_number, sale_response in enumerate(responses, 1):
        sale_approved = sale_response.get("response_code") in {"000", "001"}
        print(
            f"SALE {sale_number}/{SALES_PER_RUN} approved={sale_approved}",
            flush=True,
        )


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
