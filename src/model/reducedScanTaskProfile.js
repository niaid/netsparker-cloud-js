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
exports.ReducedScanTaskProfile = void 0;
/**
* Represents a class that carries out basic scan task profile data.
*/
class ReducedScanTaskProfile {
    static getAttributeTypeMap() {
        return ReducedScanTaskProfile.attributeTypeMap;
    }
}
exports.ReducedScanTaskProfile = ReducedScanTaskProfile;
ReducedScanTaskProfile.discriminator = undefined;
ReducedScanTaskProfile.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "isMine",
        "baseName": "IsMine",
        "type": "boolean"
    },
    {
        "name": "isPrimary",
        "baseName": "IsPrimary",
        "type": "boolean"
    },
    {
        "name": "isShared",
        "baseName": "IsShared",
        "type": "boolean"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "targetUrl",
        "baseName": "TargetUrl",
        "type": "string"
    },
    {
        "name": "scanPolicyName",
        "baseName": "ScanPolicyName",
        "type": "string"
    }
];
//# sourceMappingURL=reducedScanTaskProfile.js.map