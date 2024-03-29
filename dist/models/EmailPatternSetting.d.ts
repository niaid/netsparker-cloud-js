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
 * Represents an email address pattern which is used to ignore email disclosure issues.
 * @export
 * @interface EmailPatternSetting
 */
export interface EmailPatternSetting {
    /**
     * Gets or sets the value.
     * @type {string}
     * @memberof EmailPatternSetting
     */
    value: string;
}
/**
 * Check if a given object implements the EmailPatternSetting interface.
 */
export declare function instanceOfEmailPatternSetting(value: object): boolean;
export declare function EmailPatternSettingFromJSON(json: any): EmailPatternSetting;
export declare function EmailPatternSettingFromJSONTyped(json: any, ignoreDiscriminator: boolean): EmailPatternSetting;
export declare function EmailPatternSettingToJSON(value?: EmailPatternSetting | null): any;
