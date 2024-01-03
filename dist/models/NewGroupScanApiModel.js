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
import { ScanTimeWindowModelFromJSON, ScanTimeWindowModelToJSON, } from './ScanTimeWindowModel';
/**
 * @export
 */
export const NewGroupScanApiModelAuthenticationProfileOptionEnum = {
    DontUse: 'DontUse',
    UseMatchedProfile: 'UseMatchedProfile',
    SelectedProfile: 'SelectedProfile'
};
/**
 * Check if a given object implements the NewGroupScanApiModel interface.
 */
export function instanceOfNewGroupScanApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "websiteGroupName" in value;
    return isInstance;
}
export function NewGroupScanApiModelFromJSON(json) {
    return NewGroupScanApiModelFromJSONTyped(json, false);
}
export function NewGroupScanApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'policyId': !exists(json, 'PolicyId') ? undefined : json['PolicyId'],
        'reportPolicyId': !exists(json, 'ReportPolicyId') ? undefined : json['ReportPolicyId'],
        'authenticationProfileOption': !exists(json, 'AuthenticationProfileOption') ? undefined : json['AuthenticationProfileOption'],
        'authenticationProfileId': !exists(json, 'AuthenticationProfileId') ? undefined : json['AuthenticationProfileId'],
        'timeWindow': !exists(json, 'TimeWindow') ? undefined : ScanTimeWindowModelFromJSON(json['TimeWindow']),
        'websiteGroupName': json['WebsiteGroupName'],
        'tags': !exists(json, 'Tags') ? undefined : json['Tags'],
    };
}
export function NewGroupScanApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'PolicyId': value.policyId,
        'ReportPolicyId': value.reportPolicyId,
        'AuthenticationProfileOption': value.authenticationProfileOption,
        'AuthenticationProfileId': value.authenticationProfileId,
        'TimeWindow': ScanTimeWindowModelToJSON(value.timeWindow),
        'WebsiteGroupName': value.websiteGroupName,
        'Tags': value.tags,
    };
}
//# sourceMappingURL=NewGroupScanApiModel.js.map