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
exports.IncrementalApiModelToJSON = exports.IncrementalApiModelFromJSONTyped = exports.IncrementalApiModelFromJSON = exports.instanceOfIncrementalApiModel = void 0;
/**
 * Check if a given object implements the IncrementalApiModel interface.
 */
function instanceOfIncrementalApiModel(value) {
    if (!('baseScanId' in value))
        return false;
    return true;
}
exports.instanceOfIncrementalApiModel = instanceOfIncrementalApiModel;
function IncrementalApiModelFromJSON(json) {
    return IncrementalApiModelFromJSONTyped(json, false);
}
exports.IncrementalApiModelFromJSON = IncrementalApiModelFromJSON;
function IncrementalApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'isMaxScanDurationEnabled': json['IsMaxScanDurationEnabled'] == null ? undefined : json['IsMaxScanDurationEnabled'],
        'maxScanDuration': json['MaxScanDuration'] == null ? undefined : json['MaxScanDuration'],
        'agentGroupName': json['AgentGroupName'] == null ? undefined : json['AgentGroupName'],
        'agentName': json['AgentName'] == null ? undefined : json['AgentName'],
        'baseScanId': json['BaseScanId'],
    };
}
exports.IncrementalApiModelFromJSONTyped = IncrementalApiModelFromJSONTyped;
function IncrementalApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'IsMaxScanDurationEnabled': value['isMaxScanDurationEnabled'],
        'MaxScanDuration': value['maxScanDuration'],
        'AgentGroupName': value['agentGroupName'],
        'AgentName': value['agentName'],
        'BaseScanId': value['baseScanId'],
    };
}
exports.IncrementalApiModelToJSON = IncrementalApiModelToJSON;
//# sourceMappingURL=IncrementalApiModel.js.map