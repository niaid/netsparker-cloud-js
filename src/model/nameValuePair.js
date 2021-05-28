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
exports.NameValuePair = void 0;
/**
* Represents a name / value pair model
*/
class NameValuePair {
    static getAttributeTypeMap() {
        return NameValuePair.attributeTypeMap;
    }
}
exports.NameValuePair = NameValuePair;
NameValuePair.discriminator = undefined;
NameValuePair.attributeTypeMap = [
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "value",
        "baseName": "Value",
        "type": "string"
    },
    {
        "name": "isEncrypted",
        "baseName": "IsEncrypted",
        "type": "boolean"
    }
];
//# sourceMappingURL=nameValuePair.js.map