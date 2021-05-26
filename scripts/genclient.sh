#!/bin/bash

NETSPARKER_CLOUD_SWAGGER=https://www.netsparkercloud.com/swagger/docs/v1
GENERATOR_CMD=node_modules/.bin/openapi-generator
CLIENT_SPEC=specs/netsparker.json
CLIENT_OUT=src

# if [ ! -f ${GENERATOR_CMD} ]; then
#   echo "ERROR: Cannot locate swagger client generator. Did you run 'npm install'?"
#   exit 1
# fi

echo "downloading latest swagger spec from: ${NETSPARKER_CLOUD_SWAGGER}"
if [ ! -f ${CLIENT_SPEC} ]; then
  curl ${NETSPARKER_CLOUD_SWAGGER} > ${CLIENT_SPEC}
else
  mv ${CLIENT_SPEC} ${CLIENT_SPEC}.bak
  curl ${NETSPARKER_CLOUD_SWAGGER} > ${CLIENT_SPEC}
fi

sed -i .bak "s/uuid/string/g" ${CLIENT_SPEC}

# echo "generating updated client in: ${CLIENT_OUT}"
# ${GENERATOR_CMD} config ${CLIENT_SPEC} -d ${CLIENT_OUT}

docker run --rm -v "${PWD}:/local" openapitools/openapi-generator-cli generate \
    -i /local/${CLIENT_SPEC} \
    -g typescript-node \
    --skip-validate-spec \
    -o /local/${CLIENT_OUT}
