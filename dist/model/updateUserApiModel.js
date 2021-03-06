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
exports.UpdateUserApiModel = void 0;
/**
* Represents a model for carrying out user data.
*/
class UpdateUserApiModel {
    static getAttributeTypeMap() {
        return UpdateUserApiModel.attributeTypeMap;
    }
}
exports.UpdateUserApiModel = UpdateUserApiModel;
UpdateUserApiModel.discriminator = undefined;
UpdateUserApiModel.attributeTypeMap = [
    {
        "name": "password",
        "baseName": "Password",
        "type": "string"
    },
    {
        "name": "userId",
        "baseName": "UserId",
        "type": "string"
    },
    {
        "name": "userState",
        "baseName": "UserState",
        "type": "UpdateUserApiModel.UserStateEnum"
    },
    {
        "name": "phoneNumber",
        "baseName": "PhoneNumber",
        "type": "string"
    },
    {
        "name": "accountPermissions",
        "baseName": "AccountPermissions",
        "type": "string"
    },
    {
        "name": "timezoneId",
        "baseName": "TimezoneId",
        "type": "string"
    },
    {
        "name": "websiteGroups",
        "baseName": "WebsiteGroups",
        "type": "string"
    },
    {
        "name": "websiteGroupNames",
        "baseName": "WebsiteGroupNames",
        "type": "Array<string>"
    },
    {
        "name": "scanPermissions",
        "baseName": "ScanPermissions",
        "type": "string"
    },
    {
        "name": "dateTimeFormat",
        "baseName": "DateTimeFormat",
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
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "confirmPassword",
        "baseName": "ConfirmPassword",
        "type": "string"
    },
    {
        "name": "isApiAccessEnabled",
        "baseName": "IsApiAccessEnabled",
        "type": "boolean"
    },
    {
        "name": "allowedWebsiteLimit",
        "baseName": "AllowedWebsiteLimit",
        "type": "number"
    }
];
(function (UpdateUserApiModel) {
    let UserStateEnum;
    (function (UserStateEnum) {
        UserStateEnum[UserStateEnum["Enabled"] = 'Enabled'] = "Enabled";
        UserStateEnum[UserStateEnum["Disabled"] = 'Disabled'] = "Disabled";
    })(UserStateEnum = UpdateUserApiModel.UserStateEnum || (UpdateUserApiModel.UserStateEnum = {}));
})(UpdateUserApiModel = exports.UpdateUserApiModel || (exports.UpdateUserApiModel = {}));
//# sourceMappingURL=updateUserApiModel.js.map