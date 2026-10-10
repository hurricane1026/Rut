# http-mixed-paced1000-20261010

Local Linux single frontend core study, four nginx origin workers. Frontends run serially. Runtime candidates remain opt-in; no default promotion.

Full raw logs, effective configurations and frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-mixed-paced1000-20261010`.
Raw summary SHA256: `157765149180b26b32a972102bd8836ae0c1dc2bbd278b7cca1674dd40d13667`.

Compact results retain errors and delivered request fractions. Saturated closed-loop mixed tests complete different proportions of small and large requests, so aggregate byte throughput alone is not a matched-workload comparison. Planned-rate tests report scheduling-inclusive latency separately from send-to-completion service latency. They use one outstanding request per small connection and expose unissued plans.

Only origin-pinned and paced studies explicitly pin independent reuseport origin workers. Results do not establish a universal 1.5× nginx advantage across workloads.
