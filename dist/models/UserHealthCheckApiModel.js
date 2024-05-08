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
exports.UserHealthCheckApiModelToJSON = exports.UserHealthCheckApiModelFromJSONTyped = exports.UserHealthCheckApiModelFromJSON = exports.instanceOfUserHealthCheckApiModel = void 0;
/**
 * Check if a given object implements the UserHealthCheckApiModel interface.
 */
function instanceOfUserHealthCheckApiModel(value) {
    return true;
}
exports.instanceOfUserHealthCheckApiModel = instanceOfUserHealthCheckApiModel;
function UserHealthCheckApiModelFromJSON(json) {
    return UserHealthCheckApiModelFromJSONTyped(json, false);
}
exports.UserHealthCheckApiModelFromJSON = UserHealthCheckApiModelFromJSON;
function UserHealthCheckApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'dateFormat': json['DateFormat'] == null ? undefined : json['DateFormat'],
        'displayName': json['DisplayName'] == null ? undefined : json['DisplayName'],
        'email': json['Email'] == null ? undefined : json['Email'],
        'alternateLoginEmail': json['AlternateLoginEmail'] == null ? undefined : json['AlternateLoginEmail'],
        'timeZoneInfo': json['TimeZoneInfo'] == null ? undefined : json['TimeZoneInfo'],
    };
}
exports.UserHealthCheckApiModelFromJSONTyped = UserHealthCheckApiModelFromJSONTyped;
function UserHealthCheckApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'DateFormat': value['dateFormat'],
        'DisplayName': value['displayName'],
        'Email': value['email'],
        'AlternateLoginEmail': value['alternateLoginEmail'],
        'TimeZoneInfo': value['timeZoneInfo'],
    };
}
exports.UserHealthCheckApiModelToJSON = UserHealthCheckApiModelToJSON;
//# sourceMappingURL=UserHealthCheckApiModel.js.map