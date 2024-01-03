"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentGroupApiNewModelToJSON = exports.AgentGroupApiNewModelFromJSONTyped = exports.AgentGroupApiNewModelFromJSON = exports.instanceOfAgentGroupApiNewModel = void 0;
/**
 * Check if a given object implements the AgentGroupApiNewModel interface.
 */
function instanceOfAgentGroupApiNewModel(value) {
    let isInstance = true;
    isInstance = isInstance && "agents" in value;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfAgentGroupApiNewModel = instanceOfAgentGroupApiNewModel;
function AgentGroupApiNewModelFromJSON(json) {
    return AgentGroupApiNewModelFromJSONTyped(json, false);
}
exports.AgentGroupApiNewModelFromJSON = AgentGroupApiNewModelFromJSON;
function AgentGroupApiNewModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'agents': json['Agents'],
        'name': json['Name'],
    };
}
exports.AgentGroupApiNewModelFromJSONTyped = AgentGroupApiNewModelFromJSONTyped;
function AgentGroupApiNewModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Agents': value.agents,
        'Name': value.name,
    };
}
exports.AgentGroupApiNewModelToJSON = AgentGroupApiNewModelToJSON;
//# sourceMappingURL=AgentGroupApiNewModel.js.map