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
exports.HeaderAuthenticationModel = void 0;
/**
* Represents a model for carrying out header authentication setttings.
*/
class HeaderAuthenticationModel {
    static getAttributeTypeMap() {
        return HeaderAuthenticationModel.attributeTypeMap;
    }
}
exports.HeaderAuthenticationModel = HeaderAuthenticationModel;
HeaderAuthenticationModel.discriminator = undefined;
HeaderAuthenticationModel.attributeTypeMap = [
    {
        "name": "headers",
        "baseName": "Headers",
        "type": "Array<CustomHttpHeaderModel>"
    },
    {
        "name": "isEnabled",
        "baseName": "IsEnabled",
        "type": "boolean"
    }
];
//# sourceMappingURL=headerAuthenticationModel.js.map