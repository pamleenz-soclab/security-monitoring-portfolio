-- Local normalized investigation database queries.

-- Sign-in type counts.
SELECT sign_in_type, COUNT(*) AS events,
       SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) AS successes,
       SUM(CASE WHEN result = 'failure' THEN 1 ELSE 0 END) AS failures
FROM signins
GROUP BY sign_in_type
ORDER BY events DESC;

-- Authentication steps for the incident user.
SELECT s.created_utc, s.user_principal_name, s.ip_address,
       a.authentication_method, a.result_detail, a.succeeded,
       s.result, s.correlation_id, s.session_id
FROM signins s
JOIN authentication_steps a ON a.sign_in_id = s.sign_in_id
WHERE s.user_principal_name = 'maya.chen@compliant-secure.example.invalid'
ORDER BY s.created_utc, a.step_utc;

-- Same-session activity.
SELECT created_utc, sign_in_type, app_display_name, resource_display_name,
       result, correlation_id, request_id, unique_token_identifier
FROM signins
WHERE session_id = 'e7d719e9-7a02-5fc3-9b43-9edd645625d0'
ORDER BY created_utc;
