/* tslint:disable */
/* eslint-disable */
/**
 * Invicti Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import { exists } from '../runtime';
import { ReducedTeamDtoFromJSON, ReducedTeamDtoToJSON, } from './ReducedTeamDto';
import { RoleWebsiteGroupMappingDtoFromJSON, RoleWebsiteGroupMappingDtoToJSON, } from './RoleWebsiteGroupMappingDto';
/**
 * Check if a given object implements the MemberInvitationDto interface.
 */
export function instanceOfMemberInvitationDto(value) {
    let isInstance = true;
    return isInstance;
}
export function MemberInvitationDtoFromJSON(json) {
    return MemberInvitationDtoFromJSONTyped(json, false);
}
export function MemberInvitationDtoFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'accountId': !exists(json, 'AccountId') ? undefined : json['AccountId'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'email': !exists(json, 'Email') ? undefined : json['Email'],
        'isApiAccessEnabled': !exists(json, 'IsApiAccessEnabled') ? undefined : json['IsApiAccessEnabled'],
        'phoneNumber': !exists(json, 'PhoneNumber') ? undefined : json['PhoneNumber'],
        'allowedWebsiteLimit': !exists(json, 'AllowedWebsiteLimit') ? undefined : json['AllowedWebsiteLimit'],
        'alternateLoginEmail': !exists(json, 'AlternateLoginEmail') ? undefined : json['AlternateLoginEmail'],
        'inUse': !exists(json, 'InUse') ? undefined : json['InUse'],
        'teams': !exists(json, 'Teams') ? undefined : (json['Teams'].map(ReducedTeamDtoFromJSON)),
        'roleWebsiteGroupMappings': !exists(json, 'RoleWebsiteGroupMappings') ? undefined : (json['RoleWebsiteGroupMappings'].map(RoleWebsiteGroupMappingDtoFromJSON)),
        'isAlternateLoginEmail': !exists(json, 'IsAlternateLoginEmail') ? undefined : json['IsAlternateLoginEmail'],
        'onlySsoLogin': !exists(json, 'OnlySsoLogin') ? undefined : json['OnlySsoLogin'],
    };
}
export function MemberInvitationDtoToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'AccountId': value.accountId,
        'Name': value.name,
        'Email': value.email,
        'IsApiAccessEnabled': value.isApiAccessEnabled,
        'PhoneNumber': value.phoneNumber,
        'AllowedWebsiteLimit': value.allowedWebsiteLimit,
        'AlternateLoginEmail': value.alternateLoginEmail,
        'InUse': value.inUse,
        'Teams': value.teams === undefined ? undefined : (value.teams.map(ReducedTeamDtoToJSON)),
        'RoleWebsiteGroupMappings': value.roleWebsiteGroupMappings === undefined ? undefined : (value.roleWebsiteGroupMappings.map(RoleWebsiteGroupMappingDtoToJSON)),
        'IsAlternateLoginEmail': value.isAlternateLoginEmail,
        'OnlySsoLogin': value.onlySsoLogin,
    };
}
//# sourceMappingURL=MemberInvitationDto.js.map