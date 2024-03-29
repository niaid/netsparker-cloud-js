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
    let isInstance = true;
    isInstance = isInstance && "value" in value;

    return isInstance;
}

export function FormAuthenticationCustomScriptFromJSON(json: any): FormAuthenticationCustomScript {
    return FormAuthenticationCustomScriptFromJSONTyped(json, false);
}

export function FormAuthenticationCustomScriptFromJSONTyped(json: any, ignoreDiscriminator: boolean): FormAuthenticationCustomScript {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'value': json['Value'],
    };
}

export function FormAuthenticationCustomScriptToJSON(value?: FormAuthenticationCustomScript | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Value': value.value,
    };
}

