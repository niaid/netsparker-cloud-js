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
exports.ResponseFields = void 0;
/**
* Represents a oauth2 response model.
*/
class ResponseFields {
    static getAttributeTypeMap() {
        return ResponseFields.attributeTypeMap;
    }
}
exports.ResponseFields = ResponseFields;
ResponseFields.discriminator = undefined;
ResponseFields.attributeTypeMap = [
    {
        "name": "accessToken",
        "baseName": "AccessToken",
        "type": "string"
    },
    {
        "name": "refreshToken",
        "baseName": "RefreshToken",
        "type": "string"
    },
    {
        "name": "expire",
        "baseName": "Expire",
        "type": "string"
    },
    {
        "name": "tokenType",
        "baseName": "TokenType",
        "type": "string"
    },
    {
        "name": "isTokenTypeFixed",
        "baseName": "IsTokenTypeFixed",
        "type": "boolean"
    }
];
//# sourceMappingURL=responseFields.js.map