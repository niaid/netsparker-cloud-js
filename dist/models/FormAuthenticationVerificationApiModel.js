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
exports.FormAuthenticationVerificationApiModelToJSON = exports.FormAuthenticationVerificationApiModelFromJSONTyped = exports.FormAuthenticationVerificationApiModelFromJSON = exports.instanceOfFormAuthenticationVerificationApiModel = void 0;
const OtpSettings_1 = require("./OtpSettings");
/**
 * Check if a given object implements the FormAuthenticationVerificationApiModel interface.
 */
function instanceOfFormAuthenticationVerificationApiModel(value) {
    if (!('loginFormUrl' in value))
        return false;
    if (!('password' in value))
        return false;
    if (!('scanTargetUrl' in value))
        return false;
    if (!('username' in value))
        return false;
    return true;
}
exports.instanceOfFormAuthenticationVerificationApiModel = instanceOfFormAuthenticationVerificationApiModel;
function FormAuthenticationVerificationApiModelFromJSON(json) {
    return FormAuthenticationVerificationApiModelFromJSONTyped(json, false);
}
exports.FormAuthenticationVerificationApiModelFromJSON = FormAuthenticationVerificationApiModelFromJSON;
function FormAuthenticationVerificationApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'loginFormUrl': json['LoginFormUrl'],
        'password': json['Password'],
        'scanTargetUrl': json['ScanTargetUrl'],
        'username': json['Username'],
        'otpSettings': json['OtpSettings'] == null ? undefined : (0, OtpSettings_1.OtpSettingsFromJSON)(json['OtpSettings']),
    };
}
exports.FormAuthenticationVerificationApiModelFromJSONTyped = FormAuthenticationVerificationApiModelFromJSONTyped;
function FormAuthenticationVerificationApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'LoginFormUrl': value['loginFormUrl'],
        'Password': value['password'],
        'ScanTargetUrl': value['scanTargetUrl'],
        'Username': value['username'],
        'OtpSettings': (0, OtpSettings_1.OtpSettingsToJSON)(value['otpSettings']),
    };
}
exports.FormAuthenticationVerificationApiModelToJSON = FormAuthenticationVerificationApiModelToJSON;
//# sourceMappingURL=FormAuthenticationVerificationApiModel.js.map