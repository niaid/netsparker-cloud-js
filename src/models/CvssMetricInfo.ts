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
import type { CvssScoreValue } from './CvssScoreValue';
import {
    CvssScoreValueFromJSON,
    CvssScoreValueFromJSONTyped,
    CvssScoreValueToJSON,
} from './CvssScoreValue';

/**
 * 
 * @export
 * @interface CvssMetricInfo
 */
export interface CvssMetricInfo {
    /**
     * 
     * @type {CvssScoreValue}
     * @memberof CvssMetricInfo
     */
    score?: CvssScoreValue;
    /**
     * 
     * @type {{ [key: string]: string; }}
     * @memberof CvssMetricInfo
     */
    metrics?: { [key: string]: string; };
}

/**
 * Check if a given object implements the CvssMetricInfo interface.
 */
export function instanceOfCvssMetricInfo(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function CvssMetricInfoFromJSON(json: any): CvssMetricInfo {
    return CvssMetricInfoFromJSONTyped(json, false);
}

export function CvssMetricInfoFromJSONTyped(json: any, ignoreDiscriminator: boolean): CvssMetricInfo {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'score': !exists(json, 'Score') ? undefined : CvssScoreValueFromJSON(json['Score']),
        'metrics': !exists(json, 'Metrics') ? undefined : json['Metrics'],
    };
}

export function CvssMetricInfoToJSON(value?: CvssMetricInfo | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Score': CvssScoreValueToJSON(value.score),
        'Metrics': value.metrics,
    };
}

