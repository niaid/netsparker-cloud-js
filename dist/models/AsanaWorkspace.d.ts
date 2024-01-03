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
 *
 * @export
 * @interface AsanaWorkspace
 */
export interface AsanaWorkspace {
    /**
     *
     * @type {string}
     * @memberof AsanaWorkspace
     */
    gid?: string;
    /**
     *
     * @type {string}
     * @memberof AsanaWorkspace
     */
    name?: string;
}
/**
 * Check if a given object implements the AsanaWorkspace interface.
 */
export declare function instanceOfAsanaWorkspace(value: object): boolean;
export declare function AsanaWorkspaceFromJSON(json: any): AsanaWorkspace;
export declare function AsanaWorkspaceFromJSONTyped(json: any, ignoreDiscriminator: boolean): AsanaWorkspace;
export declare function AsanaWorkspaceToJSON(value?: AsanaWorkspace | null): any;