-- Adapt names to the DNS/NetFlow schema. request_bytes must be client-to-server only.
WITH hourly AS (
  SELECT
    source_ip,
    DATE_TRUNC('hour', event_time) AS hour,
    COUNT(*) AS requests,
    COUNT(DISTINCT query_name) AS unique_queries,
    SUM(request_bytes) AS request_bytes
  FROM dns_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '14 days'
  GROUP BY source_ip, DATE_TRUNC('hour', event_time)
), baseline AS (
  SELECT
    source_ip,
    AVG(request_bytes) AS avg_bytes,
    STDDEV_POP(request_bytes) AS std_bytes,
    AVG(requests) AS avg_requests,
    STDDEV_POP(requests) AS std_requests
  FROM hourly
  GROUP BY source_ip
)
SELECT h.*,
       (h.request_bytes-b.avg_bytes)/NULLIF(b.std_bytes,0) AS byte_z,
       (h.requests-b.avg_requests)/NULLIF(b.std_requests,0) AS request_z
FROM hourly h
JOIN baseline b USING (source_ip)
WHERE (h.request_bytes-b.avg_bytes)/NULLIF(b.std_bytes,0) >= 3
   OR (h.requests-b.avg_requests)/NULLIF(b.std_requests,0) >= 3;
