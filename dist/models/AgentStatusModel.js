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
exports.AgentStatusModelToJSON = exports.AgentStatusModelFromJSONTyped = exports.AgentStatusModelFromJSON = exports.instanceOfAgentStatusModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the AgentStatusModel interface.
 */
function instanceOfAgentStatusModel(value) {
    let isInstance = true;
    isInstance = isInstance && "agentId" in value;
    return isInstance;
}
exports.instanceOfAgentStatusModel = instanceOfAgentStatusModel;
function AgentStatusModelFromJSON(json) {
    return AgentStatusModelFromJSONTyped(json, false);
}
exports.AgentStatusModelFromJSON = AgentStatusModelFromJSON;
function AgentStatusModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'agentId': json['AgentId'],
        'status': !(0, runtime_1.exists)(json, 'Status') ? undefined : json['Status'],
    };
}
exports.AgentStatusModelFromJSONTyped = AgentStatusModelFromJSONTyped;
function AgentStatusModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AgentId': value.agentId,
        'Status': value.status,
    };
}
exports.AgentStatusModelToJSON = AgentStatusModelToJSON;
//# sourceMappingURL=AgentStatusModel.js.map