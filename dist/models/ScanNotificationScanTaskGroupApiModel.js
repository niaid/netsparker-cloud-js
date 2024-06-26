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
exports.ScanNotificationScanTaskGroupApiModelToJSON = exports.ScanNotificationScanTaskGroupApiModelFromJSONTyped = exports.ScanNotificationScanTaskGroupApiModelFromJSON = exports.instanceOfScanNotificationScanTaskGroupApiModel = void 0;
/**
 * Check if a given object implements the ScanNotificationScanTaskGroupApiModel interface.
 */
function instanceOfScanNotificationScanTaskGroupApiModel(value) {
    return true;
}
exports.instanceOfScanNotificationScanTaskGroupApiModel = instanceOfScanNotificationScanTaskGroupApiModel;
function ScanNotificationScanTaskGroupApiModelFromJSON(json) {
    return ScanNotificationScanTaskGroupApiModelFromJSONTyped(json, false);
}
exports.ScanNotificationScanTaskGroupApiModelFromJSON = ScanNotificationScanTaskGroupApiModelFromJSON;
function ScanNotificationScanTaskGroupApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'websiteId': json['WebsiteId'] == null ? undefined : json['WebsiteId'],
        'scanTaskGroupName': json['ScanTaskGroupName'] == null ? undefined : json['ScanTaskGroupName'],
        'scanTaskGroupId': json['ScanTaskGroupId'] == null ? undefined : json['ScanTaskGroupId'],
    };
}
exports.ScanNotificationScanTaskGroupApiModelFromJSONTyped = ScanNotificationScanTaskGroupApiModelFromJSONTyped;
function ScanNotificationScanTaskGroupApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'WebsiteId': value['websiteId'],
        'ScanTaskGroupName': value['scanTaskGroupName'],
        'ScanTaskGroupId': value['scanTaskGroupId'],
    };
}
exports.ScanNotificationScanTaskGroupApiModelToJSON = ScanNotificationScanTaskGroupApiModelToJSON;
//# sourceMappingURL=ScanNotificationScanTaskGroupApiModel.js.map