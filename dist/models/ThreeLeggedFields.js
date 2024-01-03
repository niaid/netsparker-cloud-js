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
import { OtpSettingsFromJSON, OtpSettingsToJSON, } from './OtpSettings';
/**
 * Check if a given object implements the ThreeLeggedFields interface.
 */
export function instanceOfThreeLeggedFields(value) {
    let isInstance = true;
    return isInstance;
}
export function ThreeLeggedFieldsFromJSON(json) {
    return ThreeLeggedFieldsFromJSONTyped(json, false);
}
export function ThreeLeggedFieldsFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'enabled': !exists(json, 'Enabled') ? undefined : json['Enabled'],
        'username': !exists(json, 'Username') ? undefined : json['Username'],
        'password': !exists(json, 'Password') ? undefined : json['Password'],
        'otpSettings': !exists(json, 'OtpSettings') ? undefined : OtpSettingsFromJSON(json['OtpSettings']),
        'customScripts': !exists(json, 'CustomScripts') ? undefined : json['CustomScripts'],
    };
}
export function ThreeLeggedFieldsToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Enabled': value.enabled,
        'Username': value.username,
        'Password': value.password,
        'OtpSettings': OtpSettingsToJSON(value.otpSettings),
        'CustomScripts': value.customScripts,
    };
}
//# sourceMappingURL=ThreeLeggedFields.js.map