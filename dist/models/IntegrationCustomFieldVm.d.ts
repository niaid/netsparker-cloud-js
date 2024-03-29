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
import type { FileCache } from './FileCache';
/**
 *
 * @export
 * @interface IntegrationCustomFieldVm
 */
export interface IntegrationCustomFieldVm {
    /**
     *
     * @type {FileCache}
     * @memberof IntegrationCustomFieldVm
     */
    file?: FileCache;
    /**
     *
     * @type {string}
     * @memberof IntegrationCustomFieldVm
     */
    name: string;
    /**
     *
     * @type {string}
     * @memberof IntegrationCustomFieldVm
     */
    value?: string;
    /**
     *
     * @type {string}
     * @memberof IntegrationCustomFieldVm
     */
    inputType?: IntegrationCustomFieldVmInputTypeEnum;
}
/**
 * @export
 */
export declare const IntegrationCustomFieldVmInputTypeEnum: {
    readonly Text: "Text";
    readonly Password: "Password";
    readonly Textarea: "Textarea";
    readonly FileUpload: "FileUpload";
    readonly Complex: "Complex";
};
export type IntegrationCustomFieldVmInputTypeEnum = typeof IntegrationCustomFieldVmInputTypeEnum[keyof typeof IntegrationCustomFieldVmInputTypeEnum];
/**
 * Check if a given object implements the IntegrationCustomFieldVm interface.
 */
export declare function instanceOfIntegrationCustomFieldVm(value: object): boolean;
export declare function IntegrationCustomFieldVmFromJSON(json: any): IntegrationCustomFieldVm;
export declare function IntegrationCustomFieldVmFromJSONTyped(json: any, ignoreDiscriminator: boolean): IntegrationCustomFieldVm;
export declare function IntegrationCustomFieldVmToJSON(value?: IntegrationCustomFieldVm | null): any;
