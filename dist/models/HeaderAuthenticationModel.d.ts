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
import type { CustomHttpHeaderModel } from './CustomHttpHeaderModel';
/**
 * Represents a model for carrying out header authentication setttings.
 * @export
 * @interface HeaderAuthenticationModel
 */
export interface HeaderAuthenticationModel {
    /**
     * Gets or sets the headers.
     * @type {Array<CustomHttpHeaderModel>}
     * @memberof HeaderAuthenticationModel
     */
    headers?: Array<CustomHttpHeaderModel>;
    /**
     * Gets or sets whether the authentication is enabled;
     * @type {boolean}
     * @memberof HeaderAuthenticationModel
     */
    isEnabled?: boolean;
}
/**
 * Check if a given object implements the HeaderAuthenticationModel interface.
 */
export declare function instanceOfHeaderAuthenticationModel(value: object): boolean;
export declare function HeaderAuthenticationModelFromJSON(json: any): HeaderAuthenticationModel;
export declare function HeaderAuthenticationModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): HeaderAuthenticationModel;
export declare function HeaderAuthenticationModelToJSON(value?: HeaderAuthenticationModel | null): any;
