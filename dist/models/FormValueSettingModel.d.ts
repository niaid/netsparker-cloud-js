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
 * Represents a model for carrying out form value settings.
 * @export
 * @interface FormValueSettingModel
 */
export interface FormValueSettingModel {
    /**
     * Gets or sets a value indicating whether force option is enabled.
     * @type {boolean}
     * @memberof FormValueSettingModel
     */
    force?: boolean;
    /**
     * Gets or sets the match type.
     * @type {string}
     * @memberof FormValueSettingModel
     */
    match?: FormValueSettingModelMatchEnum;
    /**
     * Gets or sets the match target.
     * @type {Array<string>}
     * @memberof FormValueSettingModel
     */
    matchTarget?: Array<FormValueSettingModelMatchTargetEnum>;
    /**
     * Gets or sets the match target.
     * @type {string}
     * @memberof FormValueSettingModel
     */
    matchTargetValue: FormValueSettingModelMatchTargetValueEnum;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof FormValueSettingModel
     */
    name: string;
    /**
     * Gets or sets the pattern.
     * @type {string}
     * @memberof FormValueSettingModel
     */
    pattern?: string;
    /**
     * Gets or sets the type.
     * @type {string}
     * @memberof FormValueSettingModel
     */
    type?: string;
    /**
     * Gets or sets the value.
     * @type {string}
     * @memberof FormValueSettingModel
     */
    value: string;
}
/**
* @export
* @enum {string}
*/
export declare enum FormValueSettingModelMatchEnum {
    RegEx = "RegEx",
    Exact = "Exact",
    Contains = "Contains",
    Starts = "Starts",
    Ends = "Ends"
}
/**
* @export
* @enum {string}
*/
export declare enum FormValueSettingModelMatchTargetEnum {
    Name = "Name",
    Label = "Label",
    Placeholder = "Placeholder",
    Id = "Id"
}
/**
* @export
* @enum {string}
*/
export declare enum FormValueSettingModelMatchTargetValueEnum {
    Name = "Name",
    Label = "Label",
    Placeholder = "Placeholder",
    Id = "Id"
}
/**
 * Check if a given object implements the FormValueSettingModel interface.
 */
export declare function instanceOfFormValueSettingModel(value: object): boolean;
export declare function FormValueSettingModelFromJSON(json: any): FormValueSettingModel;
export declare function FormValueSettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): FormValueSettingModel;
export declare function FormValueSettingModelToJSON(value?: FormValueSettingModel | null): any;
