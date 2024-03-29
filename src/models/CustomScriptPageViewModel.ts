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
 * The custom script page model
 * @export
 * @interface CustomScriptPageViewModel
 */
export interface CustomScriptPageViewModel {
    /**
     * 
     * @type {string}
     * @memberof CustomScriptPageViewModel
     */
    key: string;
    /**
     * 
     * @type {string}
     * @memberof CustomScriptPageViewModel
     */
    value: string;
}

/**
 * Check if a given object implements the CustomScriptPageViewModel interface.
 */
export function instanceOfCustomScriptPageViewModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "key" in value;
    isInstance = isInstance && "value" in value;

    return isInstance;
}

export function CustomScriptPageViewModelFromJSON(json: any): CustomScriptPageViewModel {
    return CustomScriptPageViewModelFromJSONTyped(json, false);
}

export function CustomScriptPageViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): CustomScriptPageViewModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'key': json['key'],
        'value': json['value'],
    };
}

export function CustomScriptPageViewModelToJSON(value?: CustomScriptPageViewModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'key': value.key,
        'value': value.value,
    };
}

