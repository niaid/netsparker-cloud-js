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
* Provides inputs for OAuth 2.0 Flow End Point.
*/
class OAuth2SettingEndpoint {
    static getAttributeTypeMap() {
        return OAuth2SettingEndpoint.attributeTypeMap;
    }
}
OAuth2SettingEndpoint.discriminator = undefined;
OAuth2SettingEndpoint.attributeTypeMap = [
    {
        "name": "url",
        "baseName": "Url",
        "type": "string"
    },
    {
        "name": "contentType",
        "baseName": "ContentType",
        "type": "string"
    },
    {
        "name": "method",
        "baseName": "Method",
        "type": "string"
    }
];
exports.OAuth2SettingEndpoint = OAuth2SettingEndpoint;
//# sourceMappingURL=oAuth2SettingEndpoint.js.map