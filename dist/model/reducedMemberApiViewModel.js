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
exports.ReducedMemberApiViewModel = void 0;
class ReducedMemberApiViewModel {
    static getAttributeTypeMap() {
        return ReducedMemberApiViewModel.attributeTypeMap;
    }
}
exports.ReducedMemberApiViewModel = ReducedMemberApiViewModel;
ReducedMemberApiViewModel.discriminator = undefined;
ReducedMemberApiViewModel.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "accountId",
        "baseName": "AccountId",
        "type": "string"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "email",
        "baseName": "Email",
        "type": "string"
    },
    {
        "name": "alternateLoginEmail",
        "baseName": "AlternateLoginEmail",
        "type": "string"
    }
];
//# sourceMappingURL=reducedMemberApiViewModel.js.map