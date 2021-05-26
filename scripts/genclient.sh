#!/bin/bash

NETSPARKER_CLOUD_SWAGGER=https://www.netsparkercloud.com/swagger/docs/v1
GENERATOR_CMD=node_modules/.bin/swagger-typescript-client-generator
CLIENT_SPEC=specs/netsparker.json
CLIENT_OUT=src/index.ts

if [ ! -f ${GENERATOR_CMD} ]; then
  echo "ERROR: Cannot locate swagger client generator. Did you run 'npm install'?"
  exit 1
fi

echo "downloading latest swagger spec from: ${NETSPARKER_CLOUD_SWAGGER}"
if [ ! -f ${CLIENT_SPEC} ]; then
  curl ${NETSPARKER_CLOUD_SWAGGER} > ${CLIENT_SPEC}
else
  mv ${CLIENT_SPEC} ${CLIENT_SPEC}.bak
  curl ${NETSPARKER_CLOUD_SWAGGER} > ${CLIENT_SPEC}
fi

echo "generating updated client in: ${CLIENT_OUT}"
${GENERATOR_CMD} bundle NetsparkerCloud -f ${CLIENT_SPEC} > ${CLIENT_OUT}
