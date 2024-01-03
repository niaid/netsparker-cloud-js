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
 * Represents a model for carrying out website groups data.
 * @export
 * @interface WebsiteGroupModel
 */
export interface WebsiteGroupModel {
    /**
     * Gets the display name.
     * @type {string}
     * @memberof WebsiteGroupModel
     */
    readonly displayName?: string;
    /**
     * Gets or sets the group identifier.
     * @type {string}
     * @memberof WebsiteGroupModel
     */
    id?: string;
    /**
     * Gets or sets the group name.
     * @type {string}
     * @memberof WebsiteGroupModel
     */
    name?: string;
    /**
     * Gets or sets the not verified website count.
     * @type {number}
     * @memberof WebsiteGroupModel
     */
    notVerifiedWebsiteCount?: number;
    /**
     * Gets or sets the verified website count.
     * @type {number}
     * @memberof WebsiteGroupModel
     */
    verifiedWebsiteCount?: number;
}
/**
 * Check if a given object implements the WebsiteGroupModel interface.
 */
export declare function instanceOfWebsiteGroupModel(value: object): boolean;
export declare function WebsiteGroupModelFromJSON(json: any): WebsiteGroupModel;
export declare function WebsiteGroupModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): WebsiteGroupModel;
export declare function WebsiteGroupModelToJSON(value?: WebsiteGroupModel | null): any;