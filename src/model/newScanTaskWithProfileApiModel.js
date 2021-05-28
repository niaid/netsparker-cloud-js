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
/**
* Contains properties that required to start a scan according to profile specified.
*/
class NewScanTaskWithProfileApiModel {
    static getAttributeTypeMap() {
        return NewScanTaskWithProfileApiModel.attributeTypeMap;
    }
}
NewScanTaskWithProfileApiModel.discriminator = undefined;
NewScanTaskWithProfileApiModel.attributeTypeMap = [
    {
        "name": "profileName",
        "baseName": "ProfileName",
        "type": "string"
    },
    {
        "name": "targetUri",
        "baseName": "TargetUri",
        "type": "string"
    }
];
exports.NewScanTaskWithProfileApiModel = NewScanTaskWithProfileApiModel;
//# sourceMappingURL=newScanTaskWithProfileApiModel.js.map