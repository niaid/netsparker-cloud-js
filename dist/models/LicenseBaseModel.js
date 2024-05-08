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
exports.LicenseBaseModelToJSON = exports.LicenseBaseModelFromJSONTyped = exports.LicenseBaseModelFromJSON = exports.instanceOfLicenseBaseModel = void 0;
/**
 * Check if a given object implements the LicenseBaseModel interface.
 */
function instanceOfLicenseBaseModel(value) {
    return true;
}
exports.instanceOfLicenseBaseModel = instanceOfLicenseBaseModel;
function LicenseBaseModelFromJSON(json) {
    return LicenseBaseModelFromJSONTyped(json, false);
}
exports.LicenseBaseModelFromJSON = LicenseBaseModelFromJSON;
function LicenseBaseModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'id': json['Id'] == null ? undefined : json['Id'],
        'isActive': json['IsActive'] == null ? undefined : json['IsActive'],
        'key': json['Key'] == null ? undefined : json['Key'],
        'accountCanCreateSharkScanTask': json['AccountCanCreateSharkScanTask'] == null ? undefined : json['AccountCanCreateSharkScanTask'],
    };
}
exports.LicenseBaseModelFromJSONTyped = LicenseBaseModelFromJSONTyped;
function LicenseBaseModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Id': value['id'],
        'IsActive': value['isActive'],
        'Key': value['key'],
        'AccountCanCreateSharkScanTask': value['accountCanCreateSharkScanTask'],
    };
}
exports.LicenseBaseModelToJSON = LicenseBaseModelToJSON;
//# sourceMappingURL=LicenseBaseModel.js.map