#!/bin/bash

# JSON_LOAD1=@../testDataGeneration/set31.json
# JSON_LOAD2=@../testDataGeneration/set32.json
# JSON_LOAD3=@../testDataGeneration/set33.json
# JSON_LOAD4=@../testDataGeneration/set34.json

# HEADERS='Content-Type: application/json'

# curl -v -H  "$HEADERS" \
#      -d "$JSON_LOAD1" \
#      -X POST \
#      http://127.0.0.1/nausf-auth/v1/ue-authentications

# curl -v -H  "$HEADERS" \
#      -d "$JSON_LOAD2" \
#      -X POST \
#      http://127.0.0.1/nausf-auth/v1/ue-authentications

# curl -v -H  "$HEADERS" \
#      -d "$JSON_LOAD3" \
#      -X POST \
#      http://127.0.0.1/nausf-auth/v1/ue-authentications

# curl -v -H  "$HEADERS" \
#      -d "$JSON_LOAD4" \
#      -X POST \
#      http://127.0.0.1/nausf-auth/v1/ue-authentications


JSON_LOAD1=@../testDataGeneration/set311.json
JSON_LOAD2=@../testDataGeneration/set312.json
JSON_LOAD3=@../testDataGeneration/set313.json
JSON_LOAD4=@../testDataGeneration/set314.json
JSON_LOAD5=@../testDataGeneration/set315.json
JSON_LOAD6=@../testDataGeneration/set316.json

HEADERS='Content-Type: application/json'

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD1" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD2" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD3" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD4" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD5" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications

curl -v -H  "$HEADERS" \
     -d "$JSON_LOAD6" \
     -X POST \
     http://127.0.0.1/nausf-auth/v1/ue-authentications
