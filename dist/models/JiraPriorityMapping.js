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
/**
 * @export
 */
export const JiraPriorityMappingIcSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
};
/**
 * Check if a given object implements the JiraPriorityMapping interface.
 */
export function instanceOfJiraPriorityMapping(value) {
    let isInstance = true;
    return isInstance;
}
export function JiraPriorityMappingFromJSON(json) {
    return JiraPriorityMappingFromJSONTyped(json, false);
}
export function JiraPriorityMappingFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'priority': !exists(json, 'Priority') ? undefined : json['Priority'],
        'icSeverity': !exists(json, 'IcSeverity') ? undefined : json['IcSeverity'],
    };
}
export function JiraPriorityMappingToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Priority': value.priority,
        'IcSeverity': value.icSeverity,
    };
}
//# sourceMappingURL=JiraPriorityMapping.js.map