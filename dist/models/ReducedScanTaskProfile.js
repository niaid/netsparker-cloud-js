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
exports.ReducedScanTaskProfileToJSON = exports.ReducedScanTaskProfileFromJSONTyped = exports.ReducedScanTaskProfileFromJSON = exports.instanceOfReducedScanTaskProfile = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the ReducedScanTaskProfile interface.
 */
function instanceOfReducedScanTaskProfile(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfReducedScanTaskProfile = instanceOfReducedScanTaskProfile;
function ReducedScanTaskProfileFromJSON(json) {
    return ReducedScanTaskProfileFromJSONTyped(json, false);
}
exports.ReducedScanTaskProfileFromJSON = ReducedScanTaskProfileFromJSON;
function ReducedScanTaskProfileFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'isMine': !(0, runtime_1.exists)(json, 'IsMine') ? undefined : json['IsMine'],
        'isPrimary': !(0, runtime_1.exists)(json, 'IsPrimary') ? undefined : json['IsPrimary'],
        'isShared': !(0, runtime_1.exists)(json, 'IsShared') ? undefined : json['IsShared'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
        'targetUrl': !(0, runtime_1.exists)(json, 'TargetUrl') ? undefined : json['TargetUrl'],
        'scanPolicyName': !(0, runtime_1.exists)(json, 'ScanPolicyName') ? undefined : json['ScanPolicyName'],
        'tags': !(0, runtime_1.exists)(json, 'Tags') ? undefined : json['Tags'],
    };
}
exports.ReducedScanTaskProfileFromJSONTyped = ReducedScanTaskProfileFromJSONTyped;
function ReducedScanTaskProfileToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'IsMine': value.isMine,
        'IsPrimary': value.isPrimary,
        'IsShared': value.isShared,
        'Name': value.name,
        'TargetUrl': value.targetUrl,
        'ScanPolicyName': value.scanPolicyName,
        'Tags': value.tags,
    };
}
exports.ReducedScanTaskProfileToJSON = ReducedScanTaskProfileToJSON;
//# sourceMappingURL=ReducedScanTaskProfile.js.map