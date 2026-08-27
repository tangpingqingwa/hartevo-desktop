# Exact independent review receipts

One file is permitted per reviewed PR: `pr-<number>.json`.

The reviewer creates it only after reviewing an exact current-base code head.
The receipt commit must have that reviewed head as its sole parent and may
change only the receipt file. Any later code, base, path, or receipt change
invalidates the review and requires a new independent review.
