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
export declare function instanceOfAgentGroupApiNewModel(value: object): boolean;
export declare function AgentGroupApiNewModelFromJSON(json: any): AgentGroupApiNewModel;
export declare function AgentGroupApiNewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentGroupApiNewModel;
export declare function AgentGroupApiNewModelToJSON(value?: AgentGroupApiNewModel | null): any;
