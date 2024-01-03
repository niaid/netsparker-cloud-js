"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.UpdateMemberApiModelToJSON = exports.UpdateMemberApiModelFromJSONTyped = exports.UpdateMemberApiModelFromJSON = exports.instanceOfUpdateMemberApiModel = exports.UpdateMemberApiModelStateEnum = void 0;
const runtime_1 = require("../runtime");
const RoleWebsiteGroupMappingApiModel_1 = require("./RoleWebsiteGroupMappingApiModel");
/**
 * @export
 */
exports.UpdateMemberApiModelStateEnum = {
    Enabled: 'Enabled',
    Disabled: 'Disabled'
};
/**
 * Check if a given object implements the UpdateMemberApiModel interface.
 */
function instanceOfUpdateMemberApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "email" in value;
    isInstance = isInstance && "timezoneId" in value;
    isInstance = isInstance && "dateTimeFormat" in value;
    isInstance = isInstance && "state" in value;
    return isInstance;
}
exports.instanceOfUpdateMemberApiModel = instanceOfUpdateMemberApiModel;
function UpdateMemberApiModelFromJSON(json) {
    return UpdateMemberApiModelFromJSONTyped(json, false);
}
exports.UpdateMemberApiModelFromJSON = UpdateMemberApiModelFromJSON;
function UpdateMemberApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': json['Id'],
        'name': json['Name'],
        'email': json['Email'],
        'password': !(0, runtime_1.exists)(json, 'Password') ? undefined : json['Password'],
        'confirmPassword': !(0, runtime_1.exists)(json, 'ConfirmPassword') ? undefined : json['ConfirmPassword'],
        'autoGeneratePassword': !(0, runtime_1.exists)(json, 'AutoGeneratePassword') ? undefined : json['AutoGeneratePassword'],
        'phoneNumber': !(0, runtime_1.exists)(json, 'PhoneNumber') ? undefined : json['PhoneNumber'],
        'onlySsoLogin': !(0, runtime_1.exists)(json, 'OnlySsoLogin') ? undefined : json['OnlySsoLogin'],
        'alternateLoginEmail': !(0, runtime_1.exists)(json, 'AlternateLoginEmail') ? undefined : json['AlternateLoginEmail'],
        'sendNotification': !(0, runtime_1.exists)(json, 'SendNotification') ? undefined : json['SendNotification'],
        'timezoneId': json['TimezoneId'],
        'dateTimeFormat': json['DateTimeFormat'],
        'isApiAccessEnabled': !(0, runtime_1.exists)(json, 'IsApiAccessEnabled') ? undefined : json['IsApiAccessEnabled'],
        'allowedWebsiteLimit': !(0, runtime_1.exists)(json, 'AllowedWebsiteLimit') ? undefined : json['AllowedWebsiteLimit'],
        'state': json['State'],
        'teams': !(0, runtime_1.exists)(json, 'Teams') ? undefined : json['Teams'],
        'roleWebsiteGroupMappings': !(0, runtime_1.exists)(json, 'RoleWebsiteGroupMappings') ? undefined : (json['RoleWebsiteGroupMappings'].map(RoleWebsiteGroupMappingApiModel_1.RoleWebsiteGroupMappingApiModelFromJSON)),
    };
}
exports.UpdateMemberApiModelFromJSONTyped = UpdateMemberApiModelFromJSONTyped;
function UpdateMemberApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'Name': value.name,
        'Email': value.email,
        'Password': value.password,
        'ConfirmPassword': value.confirmPassword,
        'AutoGeneratePassword': value.autoGeneratePassword,
        'PhoneNumber': value.phoneNumber,
        'OnlySsoLogin': value.onlySsoLogin,
        'AlternateLoginEmail': value.alternateLoginEmail,
        'SendNotification': value.sendNotification,
        'TimezoneId': value.timezoneId,
        'DateTimeFormat': value.dateTimeFormat,
        'IsApiAccessEnabled': value.isApiAccessEnabled,
        'AllowedWebsiteLimit': value.allowedWebsiteLimit,
        'State': value.state,
        'Teams': value.teams,
        'RoleWebsiteGroupMappings': value.roleWebsiteGroupMappings === undefined ? undefined : (value.roleWebsiteGroupMappings.map(RoleWebsiteGroupMappingApiModel_1.RoleWebsiteGroupMappingApiModelToJSON)),
    };
}
exports.UpdateMemberApiModelToJSON = UpdateMemberApiModelToJSON;
//# sourceMappingURL=UpdateMemberApiModel.js.map