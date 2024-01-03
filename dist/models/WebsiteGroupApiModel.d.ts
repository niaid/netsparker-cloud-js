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
 * Represents a model for carrying out website group data.
 * @export
 * @interface WebsiteGroupApiModel
 */
export interface WebsiteGroupApiModel {
    /**
     * Gets or sets the total websites.
     * @type {number}
     * @memberof WebsiteGroupApiModel
     */
    totalWebsites?: number;
    /**
     * Gets or sets the date which this website group created at.
     * @type {Date}
     * @memberof WebsiteGroupApiModel
     */
    createdAt?: Date;
    /**
     * Gets or sets the date which this website group was updated at.
     * @type {Date}
     * @memberof WebsiteGroupApiModel
     */
    updatedAt?: Date;
    /**
     * Gets or sets the website group identifier.
     * @type {string}
     * @memberof WebsiteGroupApiModel
     */
    id: string;
    /**
     * Gets or sets the website group name.
     * @type {string}
     * @memberof WebsiteGroupApiModel
     */
    name: string;
    /**
     * Gets or sets the website group description.
     * @type {string}
     * @memberof WebsiteGroupApiModel
     */
    description?: string;
    /**
     * Tags
     * @type {Array<string>}
     * @memberof WebsiteGroupApiModel
     */
    tags?: Array<string>;
}
/**
 * Check if a given object implements the WebsiteGroupApiModel interface.
 */
export declare function instanceOfWebsiteGroupApiModel(value: object): boolean;
export declare function WebsiteGroupApiModelFromJSON(json: any): WebsiteGroupApiModel;
export declare function WebsiteGroupApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): WebsiteGroupApiModel;
export declare function WebsiteGroupApiModelToJSON(value?: WebsiteGroupApiModel | null): any;