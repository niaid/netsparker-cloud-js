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

import { exists, mapValues } from '../runtime';
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
    let isInstance = true;

    return isInstance;
}

export function ThreeLeggedFieldsFromJSON(json: any): ThreeLeggedFields {
    return ThreeLeggedFieldsFromJSONTyped(json, false);
}

export function ThreeLeggedFieldsFromJSONTyped(json: any, ignoreDiscriminator: boolean): ThreeLeggedFields {
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

export function ThreeLeggedFieldsToJSON(value?: ThreeLeggedFields | null): any {
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

