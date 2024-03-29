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
 * Represents a model for updating a new website group.
 * @export
 * @interface UpdateWebsiteGroupApiModel
 */
export interface UpdateWebsiteGroupApiModel {
    /**
     * Gets or sets the website group identifier.
     * @type {string}
     * @memberof UpdateWebsiteGroupApiModel
     */
    id: string;
    /**
     * Gets or sets the website group name.
     * @type {string}
     * @memberof UpdateWebsiteGroupApiModel
     */
    name: string;
    /**
     * Gets or sets the website group description.
     * @type {string}
     * @memberof UpdateWebsiteGroupApiModel
     */
    description?: string;
    /**
     * Tags
     * @type {Array<string>}
     * @memberof UpdateWebsiteGroupApiModel
     */
    tags?: Array<string>;
}
/**
 * Check if a given object implements the UpdateWebsiteGroupApiModel interface.
 */
export declare function instanceOfUpdateWebsiteGroupApiModel(value: object): boolean;
export declare function UpdateWebsiteGroupApiModelFromJSON(json: any): UpdateWebsiteGroupApiModel;
export declare function UpdateWebsiteGroupApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateWebsiteGroupApiModel;
export declare function UpdateWebsiteGroupApiModelToJSON(value?: UpdateWebsiteGroupApiModel | null): any;
