#!/bin/bash

JSON_LOAD='{ "title":"foo","body":"bar", "id": 1}'
HEADERS='Content-Type: application/json'
URI=''

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications

