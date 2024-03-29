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
 * @interface BrowserSetting
 */
export interface BrowserSetting {
    /**
     *
     * @type {boolean}
     * @memberof BrowserSetting
     */
    enabled?: boolean;
    /**
     *
     * @type {string}
     * @memberof BrowserSetting
     */
    name: string;
    /**
     *
     * @type {boolean}
     * @memberof BrowserSetting
     */
    readOnly?: boolean;
}
/**
 * Check if a given object implements the BrowserSetting interface.
 */
export declare function instanceOfBrowserSetting(value: object): boolean;
export declare function BrowserSettingFromJSON(json: any): BrowserSetting;
export declare function BrowserSettingFromJSONTyped(json: any, ignoreDiscriminator: boolean): BrowserSetting;
export declare function BrowserSettingToJSON(value?: BrowserSetting | null): any;
