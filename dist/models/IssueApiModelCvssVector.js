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
import { CvssMetricModelFromJSON, CvssMetricModelToJSON, } from './CvssMetricModel';
/**
 * Check if a given object implements the IssueApiModelCvssVector interface.
 */
export function instanceOfIssueApiModelCvssVector(value) {
    let isInstance = true;
    return isInstance;
}
export function IssueApiModelCvssVectorFromJSON(json) {
    return IssueApiModelCvssVectorFromJSONTyped(json, false);
}
export function IssueApiModelCvssVectorFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'base': !exists(json, 'Base') ? undefined : CvssMetricModelFromJSON(json['Base']),
        'temporal': !exists(json, 'Temporal') ? undefined : CvssMetricModelFromJSON(json['Temporal']),
        'environmental': !exists(json, 'Environmental') ? undefined : CvssMetricModelFromJSON(json['Environmental']),
        'threat': !exists(json, 'Threat') ? undefined : CvssMetricModelFromJSON(json['Threat']),
        'supplemental': !exists(json, 'Supplemental') ? undefined : CvssMetricModelFromJSON(json['Supplemental']),
    };
}
export function IssueApiModelCvssVectorToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Base': CvssMetricModelToJSON(value.base),
        'Temporal': CvssMetricModelToJSON(value.temporal),
        'Environmental': CvssMetricModelToJSON(value.environmental),
        'Threat': CvssMetricModelToJSON(value.threat),
        'Supplemental': CvssMetricModelToJSON(value.supplemental),
    };
}
//# sourceMappingURL=IssueApiModelCvssVector.js.map