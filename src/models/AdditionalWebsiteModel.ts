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
 * 
 * @export
 * @interface AdditionalWebsiteModel
 */
export interface AdditionalWebsiteModel {
    /**
     * 
     * @type {boolean}
     * @memberof AdditionalWebsiteModel
     */
    canonical?: boolean;
    /**
     * 
     * @type {string}
     * @memberof AdditionalWebsiteModel
     */
    targetUrl?: string;
}

/**
 * Check if a given object implements the AdditionalWebsiteModel interface.
 */
export function instanceOfAdditionalWebsiteModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function AdditionalWebsiteModelFromJSON(json: any): AdditionalWebsiteModel {
    return AdditionalWebsiteModelFromJSONTyped(json, false);
}

export function AdditionalWebsiteModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AdditionalWebsiteModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'canonical': !exists(json, 'Canonical') ? undefined : json['Canonical'],
        'targetUrl': !exists(json, 'TargetUrl') ? undefined : json['TargetUrl'],
    };
}

export function AdditionalWebsiteModelToJSON(value?: AdditionalWebsiteModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Canonical': value.canonical,
        'TargetUrl': value.targetUrl,
    };
}
