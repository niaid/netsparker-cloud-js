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
exports.SensitiveKeywordSettingModel = void 0;
/**
* Represents a model for carrying out sensitive keyword settings.
*/
class SensitiveKeywordSettingModel {
    static getAttributeTypeMap() {
        return SensitiveKeywordSettingModel.attributeTypeMap;
    }
}
exports.SensitiveKeywordSettingModel = SensitiveKeywordSettingModel;
SensitiveKeywordSettingModel.discriminator = undefined;
SensitiveKeywordSettingModel.attributeTypeMap = [
    {
        "name": "pattern",
        "baseName": "Pattern",
        "type": "string"
    }
];
//# sourceMappingURL=sensitiveKeywordSettingModel.js.map