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
 * @export
 */
export const MemberApiViewModelStateEnum = {
    Enabled: 'Enabled',
    Disabled: 'Disabled'
};
/**
 * Check if a given object implements the MemberApiViewModel interface.
 */
export function instanceOfMemberApiViewModel(value) {
    let isInstance = true;
    return isInstance;
}
export function MemberApiViewModelFromJSON(json) {
    return MemberApiViewModelFromJSONTyped(json, false);
}
export function MemberApiViewModelFromJSONTyped(json, ignoreDiscriminator) {
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
        'dateTimeFormat': !exists(json, 'DateTimeFormat') ? undefined : json['DateTimeFormat'],
        'timezoneId': !exists(json, 'TimezoneId') ? undefined : json['TimezoneId'],
        'state': !exists(json, 'State') ? undefined : json['State'],
        'allowedWebsiteLimit': !exists(json, 'AllowedWebsiteLimit') ? undefined : json['AllowedWebsiteLimit'],
        'isTwoFactorAuthenticationEnabled': !exists(json, 'IsTwoFactorAuthenticationEnabled') ? undefined : json['IsTwoFactorAuthenticationEnabled'],
        'alternateLoginEmail': !exists(json, 'AlternateLoginEmail') ? undefined : json['AlternateLoginEmail'],
        'roleWebsiteGroupMappings': !exists(json, 'RoleWebsiteGroupMappings') ? undefined : (json['RoleWebsiteGroupMappings'].map(RoleWebsiteGroupMappingDtoFromJSON)),
        'teams': !exists(json, 'Teams') ? undefined : (json['Teams'].map(ReducedTeamDtoFromJSON)),
        'onlySsoLogin': !exists(json, 'OnlySsoLogin') ? undefined : json['OnlySsoLogin'],
        'createdAt': !exists(json, 'CreatedAt') ? undefined : (new Date(json['CreatedAt'])),
        'lastLoginDate': !exists(json, 'LastLoginDate') ? undefined : (new Date(json['LastLoginDate'])),
        'websiteCount': !exists(json, 'WebsiteCount') ? undefined : json['WebsiteCount'],
    };
}
export function MemberApiViewModelToJSON(value) {
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
        'DateTimeFormat': value.dateTimeFormat,
        'TimezoneId': value.timezoneId,
        'State': value.state,
        'AllowedWebsiteLimit': value.allowedWebsiteLimit,
        'IsTwoFactorAuthenticationEnabled': value.isTwoFactorAuthenticationEnabled,
        'AlternateLoginEmail': value.alternateLoginEmail,
        'RoleWebsiteGroupMappings': value.roleWebsiteGroupMappings === undefined ? undefined : (value.roleWebsiteGroupMappings.map(RoleWebsiteGroupMappingDtoToJSON)),
        'Teams': value.teams === undefined ? undefined : (value.teams.map(ReducedTeamDtoToJSON)),
        'OnlySsoLogin': value.onlySsoLogin,
        'CreatedAt': value.createdAt === undefined ? undefined : (value.createdAt.toISOString()),
        'LastLoginDate': value.lastLoginDate === undefined ? undefined : (value.lastLoginDate.toISOString()),
        'WebsiteCount': value.websiteCount,
    };
}
//# sourceMappingURL=MemberApiViewModel.js.map