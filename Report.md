# Concurrent Reversal and Batch Closing Report

## Objective

Resolve the unbalanced-batch condition produced when the connection closes
before the response to the final SALE is received.

## Implemented flow

- **TID:** `00003971`
- **SALE requests:** 4
- **SALE amount:** `0001` per request
- The four SALE requests are transmitted over the same TCP connection.
- The application reads the responses to SALE 1–3.
- After SALE 4 is transmitted, the application closes the original connection
  without reading its response.
- After three seconds, it sends a timeout REVERSAL over a new connection. The
  REVERSAL uses the same sequence number as SALE 4.
- After receiving the REVERSAL response, it waits one second and sends one
  CLOSE BATCH over a third connection.

## CLOSE BATCH totals

The debit count is calculated from the approved responses to SALE 1–3. SALE 4
is excluded because it is reversed. When all three responses are approved, the
request contains:

```text
distTrmBatchDrTxnCount : 0003
distTrmBatchDrTxnAmt   : +000000000000000003
distTrmBatchCrTxnCount : 0000
distTrmBatchCrTxnAmt   : +000000000000000000
distTrmBatchAdTxnCount : 0000
distTrmBatchAdTxnAmt   : +000000000000000000
```

Credit and adjustment count/amount fields are always set to zero.

## Conclusion

The solution resolves the unbalanced-batch problem by reversing SALE 4 with
the same sequence number before sending CLOSE BATCH. The final batch includes
only the approved, non-reversed SALE transactions, while its credit and
adjustment totals remain zero. Therefore, the batch totals remain balanced.
