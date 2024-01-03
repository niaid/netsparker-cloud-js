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
 * @interface AdditionalWebsiteModel
 */
export interface AdditionalWebsiteModel {
    /**
     *
     * @type {boolean}
     * @memberof AdditionalWebsiteModel
     */
    canonical?: boolean;
    /**
     *
     * @type {string}
     * @memberof AdditionalWebsiteModel
     */
    targetUrl?: string;
}
/**
 * Check if a given object implements the AdditionalWebsiteModel interface.
 */
export declare function instanceOfAdditionalWebsiteModel(value: object): boolean;
export declare function AdditionalWebsiteModelFromJSON(json: any): AdditionalWebsiteModel;
export declare function AdditionalWebsiteModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AdditionalWebsiteModel;
export declare function AdditionalWebsiteModelToJSON(value?: AdditionalWebsiteModel | null): any;