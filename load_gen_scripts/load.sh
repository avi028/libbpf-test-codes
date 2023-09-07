#!/bin/bash

JSON_LOAD='{ "title":"foo","body":"bar", "id": 1}'
HEADERS='Content-Type: application/json'

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications/deregister

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications/12345678-1234-1234-1234-123456789ABC/eap-session

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD" \
     -X DELETE \
     http://127.0.0.1/nausf-auth/v1/ue-authentications/12345678-1234-1234-1234-123456789ABC/eap-session

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD" \
     -X DELETE \
     http://127.0.0.1/nausf-auth/v1/ue-authentications/12345678-1234-1234-1234-123456789ABC/5g-aka-confirmation


curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD" \
     -X PUT \
     http://127.0.0.1/nausf-auth/v1/ue-authentications/12345678-1234-1234-1234-123456789ABC/5g-aka-confirmation
