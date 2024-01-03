#!/bin/bash

NETSPARKER_CLOUD_SWAGGER=https://www.netsparkercloud.com/swagger/docs/v1
GENERATOR_CMD=node_modules/.bin/openapi-generator
CLIENT_SPEC=specs/netsparker.json
CLIENT_OUT=src

if [ ! -x "$(command -v docker)" ]; then
  echo "ERROR: Generation requires Docker to be installed"
  exit 1
fi

echo "downloading latest swagger spec from: ${NETSPARKER_CLOUD_SWAGGER}"
if [ ! -f ${CLIENT_SPEC} ]; then
  curl ${NETSPARKER_CLOUD_SWAGGER} > ${CLIENT_SPEC}
else
  mv ${CLIENT_SPEC} ${CLIENT_SPEC}.bak
  curl ${NETSPARKER_CLOUD_SWAGGER} > ${CLIENT_SPEC}
fi

# https://github.com/OpenAPITools/openapi-generator/issues/3516
sed -i .bak "s/uuid/string/g" ${CLIENT_SPEC}

echo "generating updated client in: ${CLIENT_OUT}"

docker run --rm -v "${PWD}:/local" openapitools/openapi-generator-cli generate \
    -i /local/${CLIENT_SPEC} \
    -g typescript-fetch \
    --additional-properties=typescriptThreePlus=true,supportsES6=true \
    --skip-validate-spec \
    -o /local/${CLIENT_OUT} \
    2>&1 | tee /local/buildissues.txt
