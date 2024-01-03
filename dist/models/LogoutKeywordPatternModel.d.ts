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
 * Represents a model for carrying out a logout keyword pattern.
 * @export
 * @interface LogoutKeywordPatternModel
 */
export interface LogoutKeywordPatternModel {
    /**
     * Gets or sets the pattern.
     * @type {string}
     * @memberof LogoutKeywordPatternModel
     */
    pattern: string;
    /**
     * Gets or sets a value indicating whether this is regex.
     * @type {boolean}
     * @memberof LogoutKeywordPatternModel
     */
    regex?: boolean;
}
/**
 * Check if a given object implements the LogoutKeywordPatternModel interface.
 */
export declare function instanceOfLogoutKeywordPatternModel(value: object): boolean;
export declare function LogoutKeywordPatternModelFromJSON(json: any): LogoutKeywordPatternModel;
export declare function LogoutKeywordPatternModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): LogoutKeywordPatternModel;
export declare function LogoutKeywordPatternModelToJSON(value?: LogoutKeywordPatternModel | null): any;