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
exports.AuthenticationProfileViewModel = void 0;
/**
* Represents the of a Authentication Profile Model.
*/
class AuthenticationProfileViewModel {
    static getAttributeTypeMap() {
        return AuthenticationProfileViewModel.attributeTypeMap;
    }
}
exports.AuthenticationProfileViewModel = AuthenticationProfileViewModel;
AuthenticationProfileViewModel.discriminator = undefined;
AuthenticationProfileViewModel.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "id",
        "type": "string"
    },
    {
        "name": "name",
        "baseName": "name",
        "type": "string"
    },
    {
        "name": "triggeredUrl",
        "baseName": "triggeredUrl",
        "type": "string"
    },
    {
        "name": "loginUrl",
        "baseName": "loginUrl",
        "type": "string"
    },
    {
        "name": "customScripts",
        "baseName": "customScripts",
        "type": "Array<CustomScriptPageViewModel>"
    }
];
//# sourceMappingURL=authenticationProfileViewModel.js.map