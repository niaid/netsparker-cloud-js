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
export declare function instanceOfAgentGroupModel(value: object): boolean;
export declare function AgentGroupModelFromJSON(json: any): AgentGroupModel;
export declare function AgentGroupModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentGroupModel;
export declare function AgentGroupModelToJSON(value?: AgentGroupModel | null): any;
