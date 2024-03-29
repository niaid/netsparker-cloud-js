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
 * Represents a model for carrying out input auto complete settings.
 * @export
 * @interface ContentTypeModel
 */
export interface ContentTypeModel {
    /**
     * Gets or sets the content type.
     * @type {string}
     * @memberof ContentTypeModel
     */
    value: string;
}
/**
 * Check if a given object implements the ContentTypeModel interface.
 */
export declare function instanceOfContentTypeModel(value: object): boolean;
export declare function ContentTypeModelFromJSON(json: any): ContentTypeModel;
export declare function ContentTypeModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ContentTypeModel;
export declare function ContentTypeModelToJSON(value?: ContentTypeModel | null): any;
