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
 * Represents form authentication custom script.
 * @export
 * @interface FormAuthenticationCustomScript
 */
export interface FormAuthenticationCustomScript {
    /**
     * Gets or sets the custom script's value.
     * @type {string}
     * @memberof FormAuthenticationCustomScript
     */
    value: string;
}

/**
 * Check if a given object implements the FormAuthenticationCustomScript interface.
 */
export function instanceOfFormAuthenticationCustomScript(value: object): boolean {
    if (!('value' in value)) return false;
    return true;
}

export function FormAuthenticationCustomScriptFromJSON(json: any): FormAuthenticationCustomScript {
    return FormAuthenticationCustomScriptFromJSONTyped(json, false);
}

export function FormAuthenticationCustomScriptFromJSONTyped(json: any, ignoreDiscriminator: boolean): FormAuthenticationCustomScript {
    if (json == null) {
        return json;
    }
    return {
        
        'value': json['Value'],
    };
}

export function FormAuthenticationCustomScriptToJSON(value?: FormAuthenticationCustomScript | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Value': value['value'],
    };
}

