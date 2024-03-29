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
 * Represents a model for carrying out custom 404 settings.
 * @export
 * @interface Custom404SettingModel
 */
export interface Custom404SettingModel {
    /**
     * Gets or sets the Custom 404 RegEx.
     * @type {string}
     * @memberof Custom404SettingModel
     */
    custom404RegEx?: string;
    /**
     * Gets or sets a value indicating whether Auto 404 detection is disabled.
     * @type {boolean}
     * @memberof Custom404SettingModel
     */
    disableAuto404Detection?: boolean;
    /**
     * Gets or sets the maximum 404 pages to test.
     * @type {number}
     * @memberof Custom404SettingModel
     */
    max404PagesToTest: number;
    /**
     * Gets or sets the maximum 404 signature.
     * @type {number}
     * @memberof Custom404SettingModel
     */
    maximum404Signature: number;
}
/**
 * Check if a given object implements the Custom404SettingModel interface.
 */
export declare function instanceOfCustom404SettingModel(value: object): boolean;
export declare function Custom404SettingModelFromJSON(json: any): Custom404SettingModel;
export declare function Custom404SettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): Custom404SettingModel;
export declare function Custom404SettingModelToJSON(value?: Custom404SettingModel | null): any;
