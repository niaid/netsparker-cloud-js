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
 * @interface IntegrationWizardResultModel
 */
export interface IntegrationWizardResultModel {
    /**
     *
     * @type {boolean}
     * @memberof IntegrationWizardResultModel
     */
    status?: boolean;
    /**
     *
     * @type {string}
     * @memberof IntegrationWizardResultModel
     */
    errorMessage?: string;
}
/**
 * Check if a given object implements the IntegrationWizardResultModel interface.
 */
export declare function instanceOfIntegrationWizardResultModel(value: object): boolean;
export declare function IntegrationWizardResultModelFromJSON(json: any): IntegrationWizardResultModel;
export declare function IntegrationWizardResultModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): IntegrationWizardResultModel;
export declare function IntegrationWizardResultModelToJSON(value?: IntegrationWizardResultModel | null): any;
