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
 * Check if a given object implements the SecurityCheckSetting interface.
 */
export function instanceOfSecurityCheckSetting(value) {
    let isInstance = true;
    return isInstance;
}
export function SecurityCheckSettingFromJSON(json) {
    return SecurityCheckSettingFromJSONTyped(json, false);
}
export function SecurityCheckSettingFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'value': !exists(json, 'Value') ? undefined : json['Value'],
    };
}
export function SecurityCheckSettingToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Name': value.name,
        'Value': value.value,
    };
}
//# sourceMappingURL=SecurityCheckSetting.js.map