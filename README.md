# Netsparker Cloud JS

A Javascript client targeting NodeJS automatically generated from the Swagger/OpenAPI Specification provided by Netsparker for their cloud scanning service.

The specification is located at: https://www.netsparkercloud.com/swagger/docs/v1

## Quick Start

Other than a small modification to the specification which changes `UUID` type parameters to `string` type parameters (due to a [bug](https://github.com/OpenAPITools/openapi-generator/issues/3516) in the generator) the generated client is untouched. 

The generator provides a namespace from which an API specific client can be generated. The Netsparker API uses basic HTTP Authentication and there is a built in authentication strategy which can be easily configured with yout `UserID` and `Token` to make requests:

```js
import { HttpBasicAuth, TeamMembersApi } from 'netsparker-cloud-js';

const basicAuth = new HttpBasicAuth();
basicAuth.username = "<Your UserId>";
basicAuth.password = "<Your Token>";

const teams = new TeamMembersApi();
teams.setDefaultAuthentication(basicAuth);

// Print the first page list of users in your account:
teams.teamMembersList()
  .then(data => data.body.list.map(user => console.log(user)))
  .catch(err => console.error(err));
```

## Collaboration

First install/clean-install this package: `npm ci`

A simple script is included to fetch the specification using `curl` which is then provided to a development dependency module of this solution to create the client code in TypeScript. This can be ran using `npm run genclient`.

The generated code can be transpiled to JS using `npm run compile` (or simple `tsc` if you have TypeScript installed globally).

All of the above (including the install) can be done using `npm run build`.

Once updated, commit changes and push a PR.
