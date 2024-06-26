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
exports.NewGroupScanApiModelToJSON = exports.NewGroupScanApiModelFromJSONTyped = exports.NewGroupScanApiModelFromJSON = exports.instanceOfNewGroupScanApiModel = exports.NewGroupScanApiModelAuthenticationProfileOptionEnum = void 0;
const ScanTimeWindowModel_1 = require("./ScanTimeWindowModel");
/**
 * @export
 */
exports.NewGroupScanApiModelAuthenticationProfileOptionEnum = {
    DontUse: 'DontUse',
    UseMatchedProfile: 'UseMatchedProfile',
    SelectedProfile: 'SelectedProfile'
};
/**
 * Check if a given object implements the NewGroupScanApiModel interface.
 */
function instanceOfNewGroupScanApiModel(value) {
    if (!('websiteGroupName' in value))
        return false;
    return true;
}
exports.instanceOfNewGroupScanApiModel = instanceOfNewGroupScanApiModel;
function NewGroupScanApiModelFromJSON(json) {
    return NewGroupScanApiModelFromJSONTyped(json, false);
}
exports.NewGroupScanApiModelFromJSON = NewGroupScanApiModelFromJSON;
function NewGroupScanApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'policyId': json['PolicyId'] == null ? undefined : json['PolicyId'],
        'reportPolicyId': json['ReportPolicyId'] == null ? undefined : json['ReportPolicyId'],
        'authenticationProfileOption': json['AuthenticationProfileOption'] == null ? undefined : json['AuthenticationProfileOption'],
        'authenticationProfileId': json['AuthenticationProfileId'] == null ? undefined : json['AuthenticationProfileId'],
        'timeWindow': json['TimeWindow'] == null ? undefined : (0, ScanTimeWindowModel_1.ScanTimeWindowModelFromJSON)(json['TimeWindow']),
        'websiteGroupName': json['WebsiteGroupName'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
    };
}
exports.NewGroupScanApiModelFromJSONTyped = NewGroupScanApiModelFromJSONTyped;
function NewGroupScanApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'PolicyId': value['policyId'],
        'ReportPolicyId': value['reportPolicyId'],
        'AuthenticationProfileOption': value['authenticationProfileOption'],
        'AuthenticationProfileId': value['authenticationProfileId'],
        'TimeWindow': (0, ScanTimeWindowModel_1.ScanTimeWindowModelToJSON)(value['timeWindow']),
        'WebsiteGroupName': value['websiteGroupName'],
        'Tags': value['tags'],
    };
}
exports.NewGroupScanApiModelToJSON = NewGroupScanApiModelToJSON;
//# sourceMappingURL=NewGroupScanApiModel.js.map