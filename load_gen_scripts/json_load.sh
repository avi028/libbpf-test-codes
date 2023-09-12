#!/bin/bash

JSON_LOAD=@../testDataGeneration/set1.json
HEADERS='Content-Type: application/json'

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications

