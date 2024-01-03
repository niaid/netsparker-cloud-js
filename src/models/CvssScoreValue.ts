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
 * @interface CvssScoreValue
 */
export interface CvssScoreValue {
    /**
     * 
     * @type {string}
     * @memberof CvssScoreValue
     */
    readonly severity?: CvssScoreValueSeverityEnum;
    /**
     * 
     * @type {number}
     * @memberof CvssScoreValue
     */
    readonly value?: number;
}

/**
* @export
* @enum {string}
*/
export enum CvssScoreValueSeverityEnum {
    None = 'None',
    Low = 'Low',
    Medium = 'Medium',
    High = 'High',
    Critical = 'Critical'
}


/**
 * Check if a given object implements the CvssScoreValue interface.
 */
export function instanceOfCvssScoreValue(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function CvssScoreValueFromJSON(json: any): CvssScoreValue {
    return CvssScoreValueFromJSONTyped(json, false);
}

export function CvssScoreValueFromJSONTyped(json: any, ignoreDiscriminator: boolean): CvssScoreValue {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'severity': !exists(json, 'Severity') ? undefined : json['Severity'],
        'value': !exists(json, 'Value') ? undefined : json['Value'],
    };
}

export function CvssScoreValueToJSON(value?: CvssScoreValue | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
    };
}

