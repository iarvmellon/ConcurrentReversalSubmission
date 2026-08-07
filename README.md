# Concurrent Reversal Submission

This project reproduces the unbalanced-batch scenario caused by a SALE whose
response is not read before the TCP connection is closed. It then applies the
complete recovery flow: timeout REVERSAL followed by CLOSE BATCH with totals
that exclude the reversed transaction.

## Configuration

The experiment is configured in `main.py` with the following current values:

| Setting | Value | Purpose |
| --- | ---: | --- |
| Host | `10.1.110.84:28420` | SPDH server endpoint |
| TID | `00003971` | Terminal used by all requests |
| Amount | `0001` | Amount of each SALE |
| SALE count | `4` | Transactions sent during one run |
| Socket timeout | `5s` | Response timeout |
| Experiment delay | `0.01s` | Delay between transmitting SALE 4 and closing its connection |
| Reversal delay | `3s` | Delay before sending the timeout REVERSAL |
| CLOSE BATCH delay | `1s` | Delay after the REVERSAL response and before CLOSE BATCH |

The four SALE sequence numbers are loaded from `next_TRX_per_TID.json`. Their
three-digit reconciliation-period components at positions 6–8 must be
consecutive. For example:

```text
0016541970
0016541980
0016541990
0016542000
```

All SALE, REVERSAL, and CLOSE BATCH requests use transmission number `00`.

## Detailed transaction flow

### 1. Run protection and number reservation

Before starting, the process takes an exclusive non-blocking lock on
`sales_run.lock`. If another run already owns the lock, the new run stops
without transmitting anything. The application then loads and validates four
SALE reservations and checks that their reconciliation-period components are
consecutive.

### 2. First three SALE requests

The application opens the original TCP connection and sends SALE 1. It waits
for the response, parses the SPDH response code, and then sends SALE 2 over the
same connection. It repeats the same process for SALE 3.

Response codes `000` and `001` are treated as approved. Each parsed response is
kept so that the application can later calculate the debit totals of the CLOSE
BATCH request.

```text
Original TCP connection
    SALE 1 -> wait for response
    SALE 2 -> wait for response
    SALE 3 -> wait for response
```

### 3. Fourth SALE and simulated timeout

SALE 4 is transmitted through the same original TCP connection. Unlike the
first three requests, the application does not call `recv()` for its response.
It waits `EXPERIMENT_DELAY_SECONDS` (`0.01s`) and closes the original
connection. This deliberately simulates the condition where the host may have
processed the SALE but the terminal did not receive its response.

```text
Original TCP connection
    SALE 4 -> wait 0.01s -> close connection without reading response
```

The fourth SALE is not included in the list of approved responses because its
response was intentionally not read.

### 4. Timeout REVERSAL

After the original connection has closed, the application waits three
seconds. It then creates a new TCP connection and sends an SPDH timeout
REVERSAL (`FT00`).

The REVERSAL is constructed from the fourth SALE and uses:

- the same TID;
- the same amount;
- transmission number `00`;
- exactly the same sequence number as SALE 4, without incrementing it;
- an empty approval code, because the SALE response was not received.

The application waits for the REVERSAL response and closes the REVERSAL
connection. Codes `000` and `001` are reported as approved. If the response
times out or the socket fails, execution raises an error and does not continue
silently to CLOSE BATCH.

```text
New TCP connection
    timeout REVERSAL for SALE 4 -> wait for response -> close connection
```

### 5. CLOSE BATCH

After receiving the REVERSAL response, the application waits one second and
opens a third TCP connection. It builds one CLOSE BATCH request from the
captured SPDH `AO60` template and dynamically replaces:

- transmission number;
- TID;
- current date and time;
- sequence number, using the sequence of SALE 4;
- debit transaction count;
- debit transaction amount.

The captured MAC is removed after dynamic fields are changed because the
original MAC is no longer valid. The SPDH frame length is recalculated before
transmission. The application sends the request, waits for its response, and
then closes this connection. CLOSE BATCH response codes `000` and `001` are
treated as approved.

```text
Third TCP connection
    CLOSE BATCH -> wait for response -> close connection
```

## How CLOSE BATCH totals are calculated

The debit count is the number of approved responses received for SALE 1–3.
The debit amount is calculated as:

```text
debit amount = approved SALE count * AMOUNT
```

SALE 4 is excluded because it was reversed. Credit and adjustment totals are
always written explicitly as zero; values from the captured template are not
allowed to remain in these fields.

When all first three SALE requests are approved and `AMOUNT = 0001`, the
generated totals are:

```text
Totals_Batch            : 0010000003+0000000000000000030000+0000000000000000000000+000000000000000000
distTrmBatchDrTxnCount  : 0003
distTrmBatchDrTxnAmt    : +000000000000000003
distTrmBatchCrTxnCount  : 0000
distTrmBatchCrTxnAmt    : +000000000000000000
distTrmBatchAdTxnCount  : 0000
distTrmBatchAdTxnAmt    : +000000000000000000
```

If fewer than three responses are approved, both the debit count and debit
amount are reduced accordingly.

## Complete timing sequence

```text
TCP connection 1: SALE 1 -> response
                  SALE 2 -> response
                  SALE 3 -> response
                  SALE 4 -> 0.01s -> connection closed

Wait 3s

TCP connection 2: REVERSAL using SALE 4 sequence -> response -> connection closed

Wait 1s

TCP connection 3: CLOSE BATCH -> response -> connection closed
```

## Running the experiment

```bash
/bin/python /home/j.arvanitis/projects/ConcurrentReversalSubmission/main.py
```

The program prints an SPDH summary for every request and response, including
the TID, transmission number, sequence number, response code, and calculated
batch totals where available. Running the command transmits real requests to
the configured host.

## Conclusion

The solution resolves the unbalanced-batch problem by treating the fourth
SALE as a timed-out transaction, reversing it with the same sequence number,
waiting for the REVERSAL result, and only then closing the batch. The CLOSE
BATCH contains the three remaining debit transactions and explicitly reports
zero credit and adjustment transactions. Consequently, the reversed fourth
SALE is not counted in the final totals and the host batch remains balanced.
