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
 * Check if a given object implements the ServiceNowIncidentFieldPairValue interface.
 */
export function instanceOfServiceNowIncidentFieldPairValue(value) {
    let isInstance = true;
    return isInstance;
}
export function ServiceNowIncidentFieldPairValueFromJSON(json) {
    return ServiceNowIncidentFieldPairValueFromJSONTyped(json, false);
}
export function ServiceNowIncidentFieldPairValueFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'text': !exists(json, 'Text') ? undefined : json['Text'],
    };
}
export function ServiceNowIncidentFieldPairValueToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'Text': value.text,
    };
}
//# sourceMappingURL=ServiceNowIncidentFieldPairValue.js.map