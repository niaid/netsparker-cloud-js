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
export declare function instanceOfAgentGroupApiUpdateModel(value: object): boolean;
export declare function AgentGroupApiUpdateModelFromJSON(json: any): AgentGroupApiUpdateModel;
export declare function AgentGroupApiUpdateModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentGroupApiUpdateModel;
export declare function AgentGroupApiUpdateModelToJSON(value?: AgentGroupApiUpdateModel | null): any;
