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
import { exists } from '../runtime';
/**
 * Check if a given object implements the AgentSelectionModel interface.
 */
export function instanceOfAgentSelectionModel(value) {
    let isInstance = true;
    return isInstance;
}
export function AgentSelectionModelFromJSON(json) {
    return AgentSelectionModelFromJSONTyped(json, false);
}
export function AgentSelectionModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'agentId': !exists(json, 'AgentId') ? undefined : json['AgentId'],
        'websiteId': !exists(json, 'WebsiteId') ? undefined : json['WebsiteId'],
    };
}
export function AgentSelectionModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AgentId': value.agentId,
        'WebsiteId': value.websiteId,
    };
}
//# sourceMappingURL=AgentSelectionModel.js.map