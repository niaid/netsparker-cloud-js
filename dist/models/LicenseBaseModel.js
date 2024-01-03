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
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the LicenseBaseModel interface.
 */
function instanceOfLicenseBaseModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfLicenseBaseModel = instanceOfLicenseBaseModel;
function LicenseBaseModelFromJSON(json) {
    return LicenseBaseModelFromJSONTyped(json, false);
}
exports.LicenseBaseModelFromJSON = LicenseBaseModelFromJSON;
function LicenseBaseModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'isActive': !(0, runtime_1.exists)(json, 'IsActive') ? undefined : json['IsActive'],
        'key': !(0, runtime_1.exists)(json, 'Key') ? undefined : json['Key'],
        'accountCanCreateSharkScanTask': !(0, runtime_1.exists)(json, 'AccountCanCreateSharkScanTask') ? undefined : json['AccountCanCreateSharkScanTask'],
    };
}
exports.LicenseBaseModelFromJSONTyped = LicenseBaseModelFromJSONTyped;
function LicenseBaseModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'IsActive': value.isActive,
        'Key': value.key,
        'AccountCanCreateSharkScanTask': value.accountCanCreateSharkScanTask,
    };
}
exports.LicenseBaseModelToJSON = LicenseBaseModelToJSON;
//# sourceMappingURL=LicenseBaseModel.js.map