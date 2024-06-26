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
exports.StartVerificationResultToJSON = exports.StartVerificationResultFromJSONTyped = exports.StartVerificationResultFromJSON = exports.instanceOfStartVerificationResult = exports.StartVerificationResultVerifyOwnershipResultEnum = void 0;
/**
 * @export
 */
exports.StartVerificationResultVerifyOwnershipResultEnum = {
    Verified: 'Verified',
    NotVerified: 'NotVerified',
    VerificationLimitExceed: 'VerificationLimitExceed'
};
/**
 * Check if a given object implements the StartVerificationResult interface.
 */
function instanceOfStartVerificationResult(value) {
    return true;
}
exports.instanceOfStartVerificationResult = instanceOfStartVerificationResult;
function StartVerificationResultFromJSON(json) {
    return StartVerificationResultFromJSONTyped(json, false);
}
exports.StartVerificationResultFromJSON = StartVerificationResultFromJSON;
function StartVerificationResultFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'data': json['Data'] == null ? undefined : json['Data'],
        'message': json['Message'] == null ? undefined : json['Message'],
        'verifyOwnershipResult': json['VerifyOwnershipResult'] == null ? undefined : json['VerifyOwnershipResult'],
    };
}
exports.StartVerificationResultFromJSONTyped = StartVerificationResultFromJSONTyped;
function StartVerificationResultToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Data': value['data'],
        'Message': value['message'],
        'VerifyOwnershipResult': value['verifyOwnershipResult'],
    };
}
exports.StartVerificationResultToJSON = StartVerificationResultToJSON;
//# sourceMappingURL=StartVerificationResult.js.map