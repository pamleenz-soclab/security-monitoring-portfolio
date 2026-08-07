#!/usr/bin/env python3
"""Minimal normalization helper for public fixtures. Does not modify source scenarios."""
import json,sys
ALIASES={'TimeGenerated':'event_time','IPAddress':'source_ip','UserPrincipalName':'user_name_or_alias','ServicePrincipalId':'service_principal_id','CredentialId':'credential_key_id','EventID':'event_id'}
for line in sys.stdin:
    if not line.strip(): continue
    obj=json.loads(line); out={ALIASES.get(k,k):v for k,v in obj.items()}; print(json.dumps(out,sort_keys=True))
