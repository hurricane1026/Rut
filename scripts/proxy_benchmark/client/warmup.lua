wrk.method = "GET"
wrk.path = "/proxy"
wrk.headers["Host"] = "client.example"
wrk.headers["Connection"] = nil

done = function(summary, latency, requests)
    print(string.format(
        "METRICS %.0f %.0f %.0f %.0f %.0f %d %d %d %d %d",
        summary.requests,
        summary.duration,
        latency:percentile(50),
        latency:percentile(95),
        latency:percentile(99),
        summary.errors.connect,
        summary.errors.read,
        summary.errors.write,
        summary.errors.status,
        summary.errors.timeout
    ))
end
