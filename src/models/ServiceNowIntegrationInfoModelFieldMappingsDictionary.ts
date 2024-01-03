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
 * @interface ServiceNowIntegrationInfoModelFieldMappingsDictionary
 */
export interface ServiceNowIntegrationInfoModelFieldMappingsDictionary {
    /**
     * 
     * @type {Array<object>}
     * @memberof ServiceNowIntegrationInfoModelFieldMappingsDictionary
     */
    severity?: Array<object>;
}

/**
 * Check if a given object implements the ServiceNowIntegrationInfoModelFieldMappingsDictionary interface.
 */
export function instanceOfServiceNowIntegrationInfoModelFieldMappingsDictionary(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSON(json: any): ServiceNowIntegrationInfoModelFieldMappingsDictionary {
    return ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSONTyped(json, false);
}

export function ServiceNowIntegrationInfoModelFieldMappingsDictionaryFromJSONTyped(json: any, ignoreDiscriminator: boolean): ServiceNowIntegrationInfoModelFieldMappingsDictionary {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'severity': !exists(json, 'Severity') ? undefined : json['Severity'],
    };
}

export function ServiceNowIntegrationInfoModelFieldMappingsDictionaryToJSON(value?: ServiceNowIntegrationInfoModelFieldMappingsDictionary | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Severity': value.severity,
    };
}

