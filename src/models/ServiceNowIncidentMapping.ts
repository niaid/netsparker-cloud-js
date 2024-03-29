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
import type { ServiceNowIncidentMappingFieldKeyValuePair } from './ServiceNowIncidentMappingFieldKeyValuePair';
import {
    ServiceNowIncidentMappingFieldKeyValuePairFromJSON,
    ServiceNowIncidentMappingFieldKeyValuePairFromJSONTyped,
    ServiceNowIncidentMappingFieldKeyValuePairToJSON,
} from './ServiceNowIncidentMappingFieldKeyValuePair';

/**
 * 
 * @export
 * @interface ServiceNowIncidentMapping
 */
export interface ServiceNowIncidentMapping {
    /**
     * 
     * @type {string}
     * @memberof ServiceNowIncidentMapping
     */
    invictiChoice?: ServiceNowIncidentMappingInvictiChoiceEnum;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowIncidentMapping
     */
    invictiValue?: string;
    /**
     * 
     * @type {Array<ServiceNowIncidentMappingFieldKeyValuePair>}
     * @memberof ServiceNowIncidentMapping
     */
    fieldKeyValuePairs?: Array<ServiceNowIncidentMappingFieldKeyValuePair>;
}


/**
 * @export
 */
export const ServiceNowIncidentMappingInvictiChoiceEnum = {
    Severity: 'Severity'
} as const;
export type ServiceNowIncidentMappingInvictiChoiceEnum = typeof ServiceNowIncidentMappingInvictiChoiceEnum[keyof typeof ServiceNowIncidentMappingInvictiChoiceEnum];


/**
 * Check if a given object implements the ServiceNowIncidentMapping interface.
 */
export function instanceOfServiceNowIncidentMapping(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function ServiceNowIncidentMappingFromJSON(json: any): ServiceNowIncidentMapping {
    return ServiceNowIncidentMappingFromJSONTyped(json, false);
}

export function ServiceNowIncidentMappingFromJSONTyped(json: any, ignoreDiscriminator: boolean): ServiceNowIncidentMapping {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'invictiChoice': !exists(json, 'InvictiChoice') ? undefined : json['InvictiChoice'],
        'invictiValue': !exists(json, 'InvictiValue') ? undefined : json['InvictiValue'],
        'fieldKeyValuePairs': !exists(json, 'FieldKeyValuePairs') ? undefined : ((json['FieldKeyValuePairs'] as Array<any>).map(ServiceNowIncidentMappingFieldKeyValuePairFromJSON)),
    };
}

export function ServiceNowIncidentMappingToJSON(value?: ServiceNowIncidentMapping | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'InvictiChoice': value.invictiChoice,
        'InvictiValue': value.invictiValue,
        'FieldKeyValuePairs': value.fieldKeyValuePairs === undefined ? undefined : ((value.fieldKeyValuePairs as Array<any>).map(ServiceNowIncidentMappingFieldKeyValuePairToJSON)),
    };
}

