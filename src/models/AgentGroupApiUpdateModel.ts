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
 * Agent group model for updating
 * @export
 * @interface AgentGroupApiUpdateModel
 */
export interface AgentGroupApiUpdateModel {
    /**
     * Agents ids
     * @type {Array<string>}
     * @memberof AgentGroupApiUpdateModel
     */
    agents: Array<string>;
    /**
     * The identifier
     * @type {string}
     * @memberof AgentGroupApiUpdateModel
     */
    id: string;
    /**
     * The agent group name
     * @type {string}
     * @memberof AgentGroupApiUpdateModel
     */
    name: string;
}

/**
 * Check if a given object implements the AgentGroupApiUpdateModel interface.
 */
export function instanceOfAgentGroupApiUpdateModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "agents" in value;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "name" in value;

    return isInstance;
}

export function AgentGroupApiUpdateModelFromJSON(json: any): AgentGroupApiUpdateModel {
    return AgentGroupApiUpdateModelFromJSONTyped(json, false);
}

export function AgentGroupApiUpdateModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentGroupApiUpdateModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'agents': json['Agents'],
        'id': json['Id'],
        'name': json['Name'],
    };
}

export function AgentGroupApiUpdateModelToJSON(value?: AgentGroupApiUpdateModel | null): any {
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

