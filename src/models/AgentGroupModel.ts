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
 * Represents a model for carrying out agent group data.
 * @export
 * @interface AgentGroupModel
 */
export interface AgentGroupModel {
    /**
     * Agents which are in agent group
     * @type {Array<string>}
     * @memberof AgentGroupModel
     */
    agents?: Array<string>;
    /**
     * Agent group identifier
     * @type {string}
     * @memberof AgentGroupModel
     */
    id?: string;
    /**
     * Agent Group Name
     * @type {string}
     * @memberof AgentGroupModel
     */
    name?: string;
}

/**
 * Check if a given object implements the AgentGroupModel interface.
 */
export function instanceOfAgentGroupModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function AgentGroupModelFromJSON(json: any): AgentGroupModel {
    return AgentGroupModelFromJSONTyped(json, false);
}

export function AgentGroupModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentGroupModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'agents': !exists(json, 'Agents') ? undefined : json['Agents'],
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
    };
}

export function AgentGroupModelToJSON(value?: AgentGroupModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Agents': value.agents,
        'Id': value.id,
        'Name': value.name,
    };
}
