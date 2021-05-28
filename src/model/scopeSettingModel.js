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
* Represents a model for carrying out scope settings.
*/
class ScopeSettingModel {
    static getAttributeTypeMap() {
        return ScopeSettingModel.attributeTypeMap;
    }
}
ScopeSettingModel.discriminator = undefined;
ScopeSettingModel.attributeTypeMap = [
    {
        "name": "blockAdNetworks",
        "baseName": "BlockAdNetworks",
        "type": "boolean"
    },
    {
        "name": "byPassScopeForStaticChecks",
        "baseName": "ByPassScopeForStaticChecks",
        "type": "boolean"
    },
    {
        "name": "caseSensitiveScope",
        "baseName": "CaseSensitiveScope",
        "type": "boolean"
    },
    {
        "name": "contentTypeCheckEnabled",
        "baseName": "ContentTypeCheckEnabled",
        "type": "boolean"
    },
    {
        "name": "ignoredContentTypes",
        "baseName": "IgnoredContentTypes",
        "type": "Array<ContentTypeModel>"
    },
    {
        "name": "restrictedExtensions",
        "baseName": "RestrictedExtensions",
        "type": "string"
    }
];
exports.ScopeSettingModel = ScopeSettingModel;
//# sourceMappingURL=scopeSettingModel.js.map