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
/**
 * Represents an email address pattern which is used to ignore email disclosure issues.
 * @export
 * @interface EmailPatternSetting
 */
export interface EmailPatternSetting {
    /**
     * Gets or sets the value.
     * @type {string}
     * @memberof EmailPatternSetting
     */
    value: string;
}

/**
 * Check if a given object implements the EmailPatternSetting interface.
 */
export function instanceOfEmailPatternSetting(value: object): boolean {
    if (!('value' in value)) return false;
    return true;
}

export function EmailPatternSettingFromJSON(json: any): EmailPatternSetting {
    return EmailPatternSettingFromJSONTyped(json, false);
}

export function EmailPatternSettingFromJSONTyped(json: any, ignoreDiscriminator: boolean): EmailPatternSetting {
    if (json == null) {
        return json;
    }
    return {
        
        'value': json['Value'],
    };
}

export function EmailPatternSettingToJSON(value?: EmailPatternSetting | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Value': value['value'],
    };
}

