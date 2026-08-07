# Executive Summary

A synthetic cloud-security investigation confirmed an unapproved privilege-abuse sequence against an existing enterprise application. An administrator session granted tenant-wide delegated permissions, four high-risk Microsoft Graph application permissions, and a permanent Entra directory role. The same session added a client secret.

The exact client-secret key ID was used six minutes later in a successful service-principal sign-in. The issued application-only token then performed directory, SharePoint, and OneDrive enumeration, returned the content of a finance forecast file, and created a federated identity credential. The exact federated credential ID was subsequently used for another successful application sign-in and further Graph activity.

The application owner confirmed that the changes were not approved and no change ticket existed. Approved certificate rotation, CI/CD workload identity, and low-risk user consent records were separately identified and excluded.

**Incident classification:** Confirmed cloud privilege abuse.
**Identity assessment:** Possible application identity compromise.

The identity assessment is not elevated to confirmed because the logs do not contain secret material or direct evidence identifying the human operator. Delegated mailbox access was not observed, and exact permission claims for individual API requests were not available.
