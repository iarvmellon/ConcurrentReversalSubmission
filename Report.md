# Batch Closing Stress Test Report

## Test objective

The test evaluated the behavior of the payment terminal when a large number
of SALE and CLOSE BATCH requests are processed.

## Sales phase

- **Total TIDs:** 30
- **SALE requests per TID:** 30
- **Total SALE requests:** 900
- **Batch assignment:** one different batch number per SALE
- **Expected result:** 900 distinct batches were created and were ready to be
  closed independently.

## Batch-closing phase

After the SALE requests completed, the application sent the corresponding
CLOSE BATCH requests and processed each response.

## Observed behavior

All CLOSE BATCH requests completed successfully. The previous behavior, where
batch closing stopped after approximately the first 100 transactions, was not
observed in the latest test.

No response timeouts, socket errors, or incomplete batch-closing operations
were observed. All pending batches were closed without a problem.

## Pending transaction handling

Each pending SALE in `sales_transmitted.json` is identified by the combination
of its `tid` and `sequence_number`. The application removes exactly one
matching entry only after its CLOSE BATCH receives a successful response code
(`000`).

If the CLOSE BATCH response code is any value other than `000` , the SALE is not removed. The same applies when the request times out or
encounters a socket error. In all these cases, the SALE remains pending in
`sales_transmitted.json` so it can be retried. Matching on both fields prevents
a successful CLOSE for one TID from deleting a failed pending SALE belonging
to another TID with the same sequence number.

## Conclusion

The latest test completed successfully for all 30 TIDs. All 900 SALE batches
were closed, and the earlier limitation observed after approximately 100
transactions could not be reproduced. The current CLOSE BATCH flow completed
the full workload without errors.
