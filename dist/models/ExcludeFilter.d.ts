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
 * Exclude filter.
 * @export
 * @interface ExcludeFilter
 */
export interface ExcludeFilter {
    /**
     * Gets or sets the excluded SLDS.
     * @type {Array<string>}
     * @memberof ExcludeFilter
     */
    excludedSlds?: Array<string>;
    /**
     * Gets or sets the excluded TLDS.
     * @type {Array<string>}
     * @memberof ExcludeFilter
     */
    excludedTlds?: Array<string>;
    /**
     * Gets or sets the excluded ip addresses.
     * @type {Array<string>}
     * @memberof ExcludeFilter
     */
    excludedIpAddresses?: Array<string>;
    /**
     * Gets or sets the excluded domains.
     * @type {Array<string>}
     * @memberof ExcludeFilter
     */
    excludedDomains?: Array<string>;
    /**
     * Gets or sets the excluded organizations.
     * @type {Array<string>}
     * @memberof ExcludeFilter
     */
    excludedOrganizations?: Array<string>;
}
/**
 * Check if a given object implements the ExcludeFilter interface.
 */
export declare function instanceOfExcludeFilter(value: object): boolean;
export declare function ExcludeFilterFromJSON(json: any): ExcludeFilter;
export declare function ExcludeFilterFromJSONTyped(json: any, ignoreDiscriminator: boolean): ExcludeFilter;
export declare function ExcludeFilterToJSON(value?: ExcludeFilter | null): any;
