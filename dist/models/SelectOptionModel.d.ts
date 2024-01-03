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
 * Represents a name / value pair model.
 * @export
 * @interface SelectOptionModel
 */
export interface SelectOptionModel {
    /**
     * Gets or sets the label.
     * @type {string}
     * @memberof SelectOptionModel
     */
    label?: string;
    /**
     * Gets or sets the name.
     * @type {object}
     * @memberof SelectOptionModel
     */
    value?: object;
}
/**
 * Check if a given object implements the SelectOptionModel interface.
 */
export declare function instanceOfSelectOptionModel(value: object): boolean;
export declare function SelectOptionModelFromJSON(json: any): SelectOptionModel;
export declare function SelectOptionModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): SelectOptionModel;
export declare function SelectOptionModelToJSON(value?: SelectOptionModel | null): any;