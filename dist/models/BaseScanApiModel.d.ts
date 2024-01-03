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
 * Contains properties for the base scan.
 * @export
 * @interface BaseScanApiModel
 */
export interface BaseScanApiModel {
    /**
     * Gets or sets the agent name.
     * @type {string}
     * @memberof BaseScanApiModel
     */
    agentName?: string;
    /**
     * Gets or sets the base scan identifier.
     * @type {string}
     * @memberof BaseScanApiModel
     */
    baseScanId: string;
}
/**
 * Check if a given object implements the BaseScanApiModel interface.
 */
export declare function instanceOfBaseScanApiModel(value: object): boolean;
export declare function BaseScanApiModelFromJSON(json: any): BaseScanApiModel;
export declare function BaseScanApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BaseScanApiModel;
export declare function BaseScanApiModelToJSON(value?: BaseScanApiModel | null): any;
