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
exports.MemberInvitationApiViewModel = void 0;
class MemberInvitationApiViewModel {
    static getAttributeTypeMap() {
        return MemberInvitationApiViewModel.attributeTypeMap;
    }
}
exports.MemberInvitationApiViewModel = MemberInvitationApiViewModel;
MemberInvitationApiViewModel.discriminator = undefined;
MemberInvitationApiViewModel.attributeTypeMap = [
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
        "name": "isApiAccessEnabled",
        "baseName": "IsApiAccessEnabled",
        "type": "boolean"
    },
    {
        "name": "phoneNumber",
        "baseName": "PhoneNumber",
        "type": "string"
    },
    {
        "name": "allowedWebsiteLimit",
        "baseName": "AllowedWebsiteLimit",
        "type": "number"
    },
    {
        "name": "alternateLoginEmail",
        "baseName": "AlternateLoginEmail",
        "type": "string"
    },
    {
        "name": "inUse",
        "baseName": "InUse",
        "type": "boolean"
    },
    {
        "name": "teams",
        "baseName": "Teams",
        "type": "Array<ReducedTeamApiViewModel>"
    },
    {
        "name": "roleWebsiteGroupMappings",
        "baseName": "RoleWebsiteGroupMappings",
        "type": "Array<RoleWebsiteGroupMappingApiViewModel>"
    },
    {
        "name": "isAlternateLoginEmail",
        "baseName": "IsAlternateLoginEmail",
        "type": "boolean"
    },
    {
        "name": "onlySsoLogin",
        "baseName": "OnlySsoLogin",
        "type": "boolean"
    }
];
//# sourceMappingURL=memberInvitationApiViewModel.js.map