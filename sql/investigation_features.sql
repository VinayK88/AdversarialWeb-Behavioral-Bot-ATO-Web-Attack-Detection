-- Example warehouse feature view for adversarial web-traffic investigations.
-- Table/column names are illustrative and intentionally vendor-neutral.

WITH request_level AS (
    SELECT
        session_id,
        account_id,
        source_ip,
        user_agent,
        tls_fingerprint,
        endpoint_family,
        status_code,
        event_ts,
        CASE WHEN endpoint_family IN ('login', 'auth') AND status_code IN (401, 403) THEN 1 ELSE 0 END AS login_failure
    FROM web_request_events
    WHERE event_ts >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
),
session_features AS (
    SELECT
        session_id,
        COUNT(*) AS requests,
        COUNT(DISTINCT endpoint_family) AS distinct_endpoints,
        COUNT(DISTINCT user_agent) AS user_agents,
        COUNT(DISTINCT tls_fingerprint) AS tls_fingerprints,
        AVG(login_failure) AS login_fail_rate,
        AVG(CASE WHEN status_code BETWEEN 400 AND 499 THEN 1.0 ELSE 0.0 END) AS status_4xx_rate
    FROM request_level
    GROUP BY session_id
),
ip_account_graph AS (
    SELECT
        source_ip,
        COUNT(DISTINCT account_id) AS accounts_per_ip
    FROM request_level
    WHERE account_id IS NOT NULL
    GROUP BY source_ip
)
SELECT *
FROM session_features;
