/**
 * Netsparker Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { RequestFile } from './models';

/**
* Represents a model for update state a agent.
*/
export class AgentStatusModel {
    /**
    * Gets or sets the unique identifier of agent.
    */
    'agentId': string;
    /**
    * Gets or sets a value that represents the status of this agent instance.
    */
    'status'?: boolean;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "agentId",
            "baseName": "AgentId",
            "type": "string"
        },
        {
            "name": "status",
            "baseName": "Status",
            "type": "boolean"
        }    ];

    static getAttributeTypeMap() {
        return AgentStatusModel.attributeTypeMap;
    }
}

