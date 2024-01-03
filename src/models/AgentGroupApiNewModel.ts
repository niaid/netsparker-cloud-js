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
 * Represents a model for creating a agent group.
 * @export
 * @interface AgentGroupApiNewModel
 */
export interface AgentGroupApiNewModel {
    /**
     * Agent ids
     * @type {Array<string>}
     * @memberof AgentGroupApiNewModel
     */
    agents: Array<string>;
    /**
     * Agent Group Name
     * @type {string}
     * @memberof AgentGroupApiNewModel
     */
    name: string;
}

/**
 * Check if a given object implements the AgentGroupApiNewModel interface.
 */
export function instanceOfAgentGroupApiNewModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "agents" in value;
    isInstance = isInstance && "name" in value;

    return isInstance;
}

export function AgentGroupApiNewModelFromJSON(json: any): AgentGroupApiNewModel {
    return AgentGroupApiNewModelFromJSONTyped(json, false);
}

export function AgentGroupApiNewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentGroupApiNewModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'agents': json['Agents'],
        'name': json['Name'],
    };
}

export function AgentGroupApiNewModelToJSON(value?: AgentGroupApiNewModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Agents': value.agents,
        'Name': value.name,
    };
}

