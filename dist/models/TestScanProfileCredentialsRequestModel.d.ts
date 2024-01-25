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
 * The test scan profile credentials request model.
 * @export
 * @interface TestScanProfileCredentialsRequestModel
 */
export interface TestScanProfileCredentialsRequestModel {
    /**
     * Gets or sets the profile id.
     * @type {string}
     * @memberof TestScanProfileCredentialsRequestModel
     */
    profileId: string;
    /**
     * Gets or sets the URL.
     * @type {string}
     * @memberof TestScanProfileCredentialsRequestModel
     */
    url: string;
}
/**
 * Check if a given object implements the TestScanProfileCredentialsRequestModel interface.
 */
export declare function instanceOfTestScanProfileCredentialsRequestModel(value: object): boolean;
export declare function TestScanProfileCredentialsRequestModelFromJSON(json: any): TestScanProfileCredentialsRequestModel;
export declare function TestScanProfileCredentialsRequestModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): TestScanProfileCredentialsRequestModel;
export declare function TestScanProfileCredentialsRequestModelToJSON(value?: TestScanProfileCredentialsRequestModel | null): any;
