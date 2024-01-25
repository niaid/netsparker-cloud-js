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
 * Represents a model for deleting a agent group.
 * @export
 * @interface AgentGroupApiDeleteModel
 */
export interface AgentGroupApiDeleteModel {
    /**
     * The identifier
     * @type {string}
     * @memberof AgentGroupApiDeleteModel
     */
    name: string;
}
/**
 * Check if a given object implements the AgentGroupApiDeleteModel interface.
 */
export declare function instanceOfAgentGroupApiDeleteModel(value: object): boolean;
export declare function AgentGroupApiDeleteModelFromJSON(json: any): AgentGroupApiDeleteModel;
export declare function AgentGroupApiDeleteModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentGroupApiDeleteModel;
export declare function AgentGroupApiDeleteModelToJSON(value?: AgentGroupApiDeleteModel | null): any;
