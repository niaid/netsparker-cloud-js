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

import { mapValues } from '../runtime';
import type { OtpSettings } from './OtpSettings';
import {
    OtpSettingsFromJSON,
    OtpSettingsFromJSONTyped,
    OtpSettingsToJSON,
} from './OtpSettings';

/**
 * Represents 3-legged model for oauth2.
 * @export
 * @interface ThreeLeggedFields
 */
export interface ThreeLeggedFields {
    /**
     * .
     *             Gets or sets the enabled value
     * @type {boolean}
     * @memberof ThreeLeggedFields
     */
    enabled?: boolean;
    /**
     * .
     *             Gets or sets the username
     * @type {string}
     * @memberof ThreeLeggedFields
     */
    username?: string;
    /**
     * .
     *             Gets or sets the password
     * @type {string}
     * @memberof ThreeLeggedFields
     */
    password?: string;
    /**
     * 
     * @type {OtpSettings}
     * @memberof ThreeLeggedFields
     */
    otpSettings?: OtpSettings;
    /**
     * .
     *             Gets or sets the custom scripts
     * @type {Array<string>}
     * @memberof ThreeLeggedFields
     */
    customScripts?: Array<string>;
}

/**
 * Check if a given object implements the ThreeLeggedFields interface.
 */
export function instanceOfThreeLeggedFields(value: object): boolean {
    return true;
}

export function ThreeLeggedFieldsFromJSON(json: any): ThreeLeggedFields {
    return ThreeLeggedFieldsFromJSONTyped(json, false);
}

export function ThreeLeggedFieldsFromJSONTyped(json: any, ignoreDiscriminator: boolean): ThreeLeggedFields {
    if (json == null) {
        return json;
    }
    return {
        
        'enabled': json['Enabled'] == null ? undefined : json['Enabled'],
        'username': json['Username'] == null ? undefined : json['Username'],
        'password': json['Password'] == null ? undefined : json['Password'],
        'otpSettings': json['OtpSettings'] == null ? undefined : OtpSettingsFromJSON(json['OtpSettings']),
        'customScripts': json['CustomScripts'] == null ? undefined : json['CustomScripts'],
    };
}

export function ThreeLeggedFieldsToJSON(value?: ThreeLeggedFields | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Enabled': value['enabled'],
        'Username': value['username'],
        'Password': value['password'],
        'OtpSettings': OtpSettingsToJSON(value['otpSettings']),
        'CustomScripts': value['customScripts'],
    };
}

