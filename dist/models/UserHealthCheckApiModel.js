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
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the UserHealthCheckApiModel interface.
 */
function instanceOfUserHealthCheckApiModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfUserHealthCheckApiModel = instanceOfUserHealthCheckApiModel;
function UserHealthCheckApiModelFromJSON(json) {
    return UserHealthCheckApiModelFromJSONTyped(json, false);
}
exports.UserHealthCheckApiModelFromJSON = UserHealthCheckApiModelFromJSON;
function UserHealthCheckApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'dateFormat': !(0, runtime_1.exists)(json, 'DateFormat') ? undefined : json['DateFormat'],
        'displayName': !(0, runtime_1.exists)(json, 'DisplayName') ? undefined : json['DisplayName'],
        'email': !(0, runtime_1.exists)(json, 'Email') ? undefined : json['Email'],
        'alternateLoginEmail': !(0, runtime_1.exists)(json, 'AlternateLoginEmail') ? undefined : json['AlternateLoginEmail'],
        'timeZoneInfo': !(0, runtime_1.exists)(json, 'TimeZoneInfo') ? undefined : json['TimeZoneInfo'],
    };
}
exports.UserHealthCheckApiModelFromJSONTyped = UserHealthCheckApiModelFromJSONTyped;
function UserHealthCheckApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'DateFormat': value.dateFormat,
        'DisplayName': value.displayName,
        'Email': value.email,
        'AlternateLoginEmail': value.alternateLoginEmail,
        'TimeZoneInfo': value.timeZoneInfo,
    };
}
exports.UserHealthCheckApiModelToJSON = UserHealthCheckApiModelToJSON;
//# sourceMappingURL=UserHealthCheckApiModel.js.map