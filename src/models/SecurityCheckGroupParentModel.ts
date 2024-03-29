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
import type { SecurityCheckGroupModel } from './SecurityCheckGroupModel';
import {
    SecurityCheckGroupModelFromJSON,
    SecurityCheckGroupModelFromJSONTyped,
    SecurityCheckGroupModelToJSON,
} from './SecurityCheckGroupModel';

/**
 * Represents a model for carrying out security check groups.
 * @export
 * @interface SecurityCheckGroupParentModel
 */
export interface SecurityCheckGroupParentModel {
    /**
     * 
     * @type {string}
     * @memberof SecurityCheckGroupParentModel
     */
    title?: string;
    /**
     * 
     * @type {Array<SecurityCheckGroupModel>}
     * @memberof SecurityCheckGroupParentModel
     */
    securityCheckGroups?: Array<SecurityCheckGroupModel>;
}

/**
 * Check if a given object implements the SecurityCheckGroupParentModel interface.
 */
export function instanceOfSecurityCheckGroupParentModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function SecurityCheckGroupParentModelFromJSON(json: any): SecurityCheckGroupParentModel {
    return SecurityCheckGroupParentModelFromJSONTyped(json, false);
}

export function SecurityCheckGroupParentModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): SecurityCheckGroupParentModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'title': !exists(json, 'Title') ? undefined : json['Title'],
        'securityCheckGroups': !exists(json, 'SecurityCheckGroups') ? undefined : ((json['SecurityCheckGroups'] as Array<any>).map(SecurityCheckGroupModelFromJSON)),
    };
}

export function SecurityCheckGroupParentModelToJSON(value?: SecurityCheckGroupParentModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Title': value.title,
        'SecurityCheckGroups': value.securityCheckGroups === undefined ? undefined : ((value.securityCheckGroups as Array<any>).map(SecurityCheckGroupModelToJSON)),
    };
}

