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
/**
 * @export
 */
export const OtpSettingsOtpTypeEnum = {
    Totp: 'Totp',
    Hotp: 'Hotp'
};
/**
 * @export
 */
export const OtpSettingsAlgorithmEnum = {
    Sha1: 'Sha1',
    Sha256: 'Sha256',
    Sha512: 'Sha512'
};
/**
 * Check if a given object implements the OtpSettings interface.
 */
export function instanceOfOtpSettings(value) {
    let isInstance = true;
    return isInstance;
}
export function OtpSettingsFromJSON(json) {
    return OtpSettingsFromJSONTyped(json, false);
}
export function OtpSettingsFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'otpType': !exists(json, 'OtpType') ? undefined : json['OtpType'],
        'secretKey': !exists(json, 'SecretKey') ? undefined : json['SecretKey'],
        'digit': !exists(json, 'Digit') ? undefined : json['Digit'],
        'period': !exists(json, 'Period') ? undefined : json['Period'],
        'algorithm': !exists(json, 'Algorithm') ? undefined : json['Algorithm'],
    };
}
export function OtpSettingsToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'OtpType': value.otpType,
        'SecretKey': value.secretKey,
        'Digit': value.digit,
        'Period': value.period,
        'Algorithm': value.algorithm,
    };
}
//# sourceMappingURL=OtpSettings.js.map