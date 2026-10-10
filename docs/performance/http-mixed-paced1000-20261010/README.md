# http-mixed-paced1000-20261010

Local Linux single frontend core study, four nginx origin workers. Frontends run serially. Runtime candidates remain opt-in; no default promotion.

Full raw logs, effective configurations and frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-mixed-paced1000-20261010`.
Raw summary SHA256: `16843c1a1ec4e3f22bc4f70b17101096aafc5fe48099be0140f8d87631b36fae`.

Compact results retain errors and delivered request fractions. Saturated closed-loop mixed tests complete different proportions of small and large requests, so aggregate byte throughput alone is not a matched-workload comparison. Planned-rate tests report scheduling-inclusive latency separately from send-to-completion service latency. They use one outstanding request per small connection and expose unissued plans.

Summary validity is based on the frozen raw result's planned, issued, completed, unissued, and unfinished request counts, plus finite client metrics and zero measurement/warmup errors. One of twelve cells lacks full completion and is excluded from `valid` conclusions; the other eleven have exact complete counts.

Only origin-pinned and paced studies explicitly pin independent reuseport origin workers. Results do not establish a universal 1.5× nginx advantage across workloads.
