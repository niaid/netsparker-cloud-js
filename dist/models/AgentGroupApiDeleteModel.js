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
exports.AgentGroupApiDeleteModelToJSON = exports.AgentGroupApiDeleteModelFromJSONTyped = exports.AgentGroupApiDeleteModelFromJSON = exports.instanceOfAgentGroupApiDeleteModel = void 0;
/**
 * Check if a given object implements the AgentGroupApiDeleteModel interface.
 */
function instanceOfAgentGroupApiDeleteModel(value) {
    if (!('name' in value))
        return false;
    return true;
}
exports.instanceOfAgentGroupApiDeleteModel = instanceOfAgentGroupApiDeleteModel;
function AgentGroupApiDeleteModelFromJSON(json) {
    return AgentGroupApiDeleteModelFromJSONTyped(json, false);
}
exports.AgentGroupApiDeleteModelFromJSON = AgentGroupApiDeleteModelFromJSON;
function AgentGroupApiDeleteModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'name': json['Name'],
    };
}
exports.AgentGroupApiDeleteModelFromJSONTyped = AgentGroupApiDeleteModelFromJSONTyped;
function AgentGroupApiDeleteModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Name': value['name'],
    };
}
exports.AgentGroupApiDeleteModelToJSON = AgentGroupApiDeleteModelToJSON;
//# sourceMappingURL=AgentGroupApiDeleteModel.js.map