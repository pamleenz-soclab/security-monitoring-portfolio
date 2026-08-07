-- The working SQLite database stores each normalised record as JSON.
-- This query illustrates credential-key correlation for the generated package.
WITH credentials AS (
  SELECT json_extract(json_record, '$.keyId') AS key_id,
         json_extract(json_record, '$.credentialType') AS credential_type,
         json_extract(json_record, '$.startDateTime') AS start_time
  FROM credential_metadata
),
signins AS (
  SELECT json_extract(json_record, '$.Id') AS signin_id,
         json_extract(json_record, '$.CreatedDateTime') AS signin_time,
         COALESCE(
           json_extract(json_record, '$.ServicePrincipalCredentialKeyId'),
           json_extract(json_record, '$.FederatedCredentialId')
         ) AS key_id,
         json_extract(json_record, '$.UniqueTokenIdentifier') AS token_id
  FROM service_principal_signins
)
SELECT c.key_id, c.credential_type, c.start_time,
       s.signin_id, s.signin_time, s.token_id,
       CASE WHEN s.signin_time >= c.start_time THEN 'valid_post_creation_use'
            ELSE 'invalid_chronology' END AS chronology_status
FROM credentials c
JOIN signins s USING (key_id)
ORDER BY s.signin_time;
