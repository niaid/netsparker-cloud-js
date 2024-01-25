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
 * Get or Set user agent for scan policy
 * @export
 * @interface ScanPolicyUserAgentModel
 */
export interface ScanPolicyUserAgentModel {
    /**
     * Get or Set agent name
     * @type {string}
     * @memberof ScanPolicyUserAgentModel
     */
    name?: string;
    /**
     * Get or Set agent Value
     * @type {string}
     * @memberof ScanPolicyUserAgentModel
     */
    value?: string;
}
/**
 * Check if a given object implements the ScanPolicyUserAgentModel interface.
 */
export declare function instanceOfScanPolicyUserAgentModel(value: object): boolean;
export declare function ScanPolicyUserAgentModelFromJSON(json: any): ScanPolicyUserAgentModel;
export declare function ScanPolicyUserAgentModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanPolicyUserAgentModel;
export declare function ScanPolicyUserAgentModelToJSON(value?: ScanPolicyUserAgentModel | null): any;
