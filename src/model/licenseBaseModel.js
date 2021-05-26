"use strict";
/**
 * Netsparker Enterprise API
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
exports.LicenseBaseModel = void 0;
/**
* Base subscription license model for carrying out license data.
*/
class LicenseBaseModel {
    static getAttributeTypeMap() {
        return LicenseBaseModel.attributeTypeMap;
    }
}
exports.LicenseBaseModel = LicenseBaseModel;
LicenseBaseModel.discriminator = undefined;
LicenseBaseModel.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "isActive",
        "baseName": "IsActive",
        "type": "boolean"
    },
    {
        "name": "key",
        "baseName": "Key",
        "type": "string"
    },
    {
        "name": "accountCanCreateSharkScanTask",
        "baseName": "AccountCanCreateSharkScanTask",
        "type": "boolean"
    }
];
//# sourceMappingURL=licenseBaseModel.js.map