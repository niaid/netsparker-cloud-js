/* tslint:disable */
/* eslint-disable */
/**
 * Invicti Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
/**
 * Check if a given object implements the DeleteAgentModel interface.
 */
export function instanceOfDeleteAgentModel(value) {
    let isInstance = true;
    isInstance = isInstance && "agentId" in value;
    return isInstance;
}
export function DeleteAgentModelFromJSON(json) {
    return DeleteAgentModelFromJSONTyped(json, false);
}
export function DeleteAgentModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'agentId': json['AgentId'],
    };
}
export function DeleteAgentModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AgentId': value.agentId,
    };
}
//# sourceMappingURL=DeleteAgentModel.js.map