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

import { mapValues } from '../runtime';
/**
 * Represents a model for deleting a agent.
 * @export
 * @interface DeleteAgentModel
 */
export interface DeleteAgentModel {
    /**
     * Gets or sets the unique identifier of agent.
     * @type {string}
     * @memberof DeleteAgentModel
     */
    agentId: string;
}

/**
 * Check if a given object implements the DeleteAgentModel interface.
 */
export function instanceOfDeleteAgentModel(value: object): boolean {
    if (!('agentId' in value)) return false;
    return true;
}

export function DeleteAgentModelFromJSON(json: any): DeleteAgentModel {
    return DeleteAgentModelFromJSONTyped(json, false);
}

export function DeleteAgentModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): DeleteAgentModel {
    if (json == null) {
        return json;
    }
    return {
        
        'agentId': json['AgentId'],
    };
}

export function DeleteAgentModelToJSON(value?: DeleteAgentModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'AgentId': value['agentId'],
    };
}

