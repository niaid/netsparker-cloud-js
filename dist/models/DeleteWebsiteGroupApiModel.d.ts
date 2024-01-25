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
 * Represents a model for deleting a website group.
 * @export
 * @interface DeleteWebsiteGroupApiModel
 */
export interface DeleteWebsiteGroupApiModel {
    /**
     * Gets or sets the website group name.
     * @type {string}
     * @memberof DeleteWebsiteGroupApiModel
     */
    name: string;
}
/**
 * Check if a given object implements the DeleteWebsiteGroupApiModel interface.
 */
export declare function instanceOfDeleteWebsiteGroupApiModel(value: object): boolean;
export declare function DeleteWebsiteGroupApiModelFromJSON(json: any): DeleteWebsiteGroupApiModel;
export declare function DeleteWebsiteGroupApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): DeleteWebsiteGroupApiModel;
export declare function DeleteWebsiteGroupApiModelToJSON(value?: DeleteWebsiteGroupApiModel | null): any;
