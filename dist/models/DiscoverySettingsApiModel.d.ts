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
 * Discovery Settings api model.
 * @export
 * @interface DiscoverySettingsApiModel
 */
export interface DiscoverySettingsApiModel {
    /**
     *
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    includedMainDomains?: string;
    /**
     * Gets or sets the included SLDS.
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    includedSlds?: string;
    /**
     * Gets or sets the included ip ranges.
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    includedIpRanges?: string;
    /**
     * Gets or sets the included organizations.
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    includedOrganizations?: string;
    /**
     *
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    excludedDomains?: string;
    /**
     * Gets or sets the excluded SLDS.
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    excludedSlds?: string;
    /**
     * Gets or sets the excluded TLDS.
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    excludedTlds?: string;
    /**
     * Gets or sets the excluded ip addresses.
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    excludedIpAddresses?: string;
    /**
     * Gets or sets the excluded organizations.
     * @type {string}
     * @memberof DiscoverySettingsApiModel
     */
    excludedOrganizations?: string;
    /**
     * Gets or sets a value indicating whether [only registered domains].
     * @type {boolean}
     * @memberof DiscoverySettingsApiModel
     */
    onlyRegisteredDomains?: boolean;
    /**
     * Gets or sets a value indicating whether [shared host matching].
     * @type {boolean}
     * @memberof DiscoverySettingsApiModel
     */
    sharedHostMatching?: boolean;
    /**
     * Gets or sets a value indicating whether [organization name matching].
     * @type {boolean}
     * @memberof DiscoverySettingsApiModel
     */
    organizationNameMatching?: boolean;
    /**
     * Gets or sets a value indicating whether [only registered domains].
     * @type {boolean}
     * @memberof DiscoverySettingsApiModel
     */
    emailMatching?: boolean;
    /**
     * Gets or sets a value indicating whether [only registered domains].
     * @type {boolean}
     * @memberof DiscoverySettingsApiModel
     */
    websitesMatching?: boolean;
    /**
     * Gets or sets a value indicating whether [only registered domains].
     * @type {boolean}
     * @memberof DiscoverySettingsApiModel
     */
    enableSlds?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof DiscoverySettingsApiModel
     */
    isRiskScoringEnabled?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof DiscoverySettingsApiModel
     */
    enableMainDomains?: boolean;
}
/**
 * Check if a given object implements the DiscoverySettingsApiModel interface.
 */
export declare function instanceOfDiscoverySettingsApiModel(value: object): boolean;
export declare function DiscoverySettingsApiModelFromJSON(json: any): DiscoverySettingsApiModel;
export declare function DiscoverySettingsApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): DiscoverySettingsApiModel;
export declare function DiscoverySettingsApiModelToJSON(value?: DiscoverySettingsApiModel | null): any;
