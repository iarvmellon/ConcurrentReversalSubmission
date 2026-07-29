"""Configurable sales runner."""
from pathlib import Path
import time

from send_packets import (
    STATE_FILE,
    reserve_message_numbers,
    save_next_sale_numbers,
    send_reversal,
    send_sale,
)
INITIAL_SEQUENCE_NUMBER = "0015304720"
INITIAL_TRANSMISSION_NUMBER = "70"

HOST = "10.1.110.84"
PORT = 28420
TIMEOUT = 5.0
TIDS = ["00003971"]
AMOUNT = "0001"
REVERSAL_AMOUNT = "1"
INCREMENT_BATCH_PER_SALE = True
reversal_delay = 0
STATE = Path(STATE_FILE)


def main():
    tid = TIDS[0]
    sale_sequence, sale_transmission = reserve_message_numbers(
        STATE,
        INITIAL_SEQUENCE_NUMBER,
        INITIAL_TRANSMISSION_NUMBER,
        increment_batch=INCREMENT_BATCH_PER_SALE,
        tid=tid,
    )
    sale_response = send_sale(
        HOST,
        PORT,
        TIMEOUT,
        sale_sequence,
        sale_transmission,
        tid,
        AMOUNT,
    )
    approval_code = sale_response.get("approval_code", "")
    sale_approved = sale_response.get("response_code") in {"000", "001"}

    # The next TRX is the reversal: same batch, next sequence component and TRN.
    save_next_sale_numbers(
        tid,
        sale_sequence,
        sale_transmission,
        increment_sequence=False,
        increment_batch=False,
    )

    # if not sale_approved or not approval_code:
    #     print("REVERSAL not sent: SALE was not approved or has no approval code")
    #     return

    time.sleep(reversal_delay)
    reversal_sequence, reversal_transmission = reserve_message_numbers(
        STATE,
        INITIAL_SEQUENCE_NUMBER,
        INITIAL_TRANSMISSION_NUMBER,
        record=False,
        increment_sequence=False,
        increment_batch=False,
        tid=tid,
    )
    send_reversal(
        HOST,
        PORT,
        TIMEOUT,
        sale_sequence,
        reversal_sequence,
        reversal_transmission,
        tid,
        REVERSAL_AMOUNT,
        approval_code,
    )

    # After the reversal, persist the counters for the next SALE.
    save_next_sale_numbers(
        tid,
        reversal_sequence,
        reversal_transmission,
        increment_batch=INCREMENT_BATCH_PER_SALE,
        reset_transmission=True,
    )


if __name__ == "__main__":
    main()
