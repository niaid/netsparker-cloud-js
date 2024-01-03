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
exports.AgentSelectionModelToJSON = exports.AgentSelectionModelFromJSONTyped = exports.AgentSelectionModelFromJSON = exports.instanceOfAgentSelectionModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the AgentSelectionModel interface.
 */
function instanceOfAgentSelectionModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfAgentSelectionModel = instanceOfAgentSelectionModel;
function AgentSelectionModelFromJSON(json) {
    return AgentSelectionModelFromJSONTyped(json, false);
}
exports.AgentSelectionModelFromJSON = AgentSelectionModelFromJSON;
function AgentSelectionModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'agentId': !(0, runtime_1.exists)(json, 'AgentId') ? undefined : json['AgentId'],
        'websiteId': !(0, runtime_1.exists)(json, 'WebsiteId') ? undefined : json['WebsiteId'],
    };
}
exports.AgentSelectionModelFromJSONTyped = AgentSelectionModelFromJSONTyped;
function AgentSelectionModelToJSON(value) {
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
exports.AgentSelectionModelToJSON = AgentSelectionModelToJSON;
//# sourceMappingURL=AgentSelectionModel.js.map