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
import type { ScanPolicyOptimizerOptions } from './ScanPolicyOptimizerOptions';
import type { WebsiteGroupModel } from './WebsiteGroupModel';
/**
 * Represents a from for carrying out scan policy setting data.
 * @export
 * @interface ScanPolicySettingItemApiModel
 */
export interface ScanPolicySettingItemApiModel {
    /**
     * Gets or sets the description.
     * @type {string}
     * @memberof ScanPolicySettingItemApiModel
     */
    description?: string;
    /**
     * Gets or sets the set of website groups associated with this instance.
     * @type {Array<WebsiteGroupModel>}
     * @memberof ScanPolicySettingItemApiModel
     */
    groups?: Array<WebsiteGroupModel>;
    /**
     * Gets or sets the identifier.
     * @type {string}
     * @memberof ScanPolicySettingItemApiModel
     */
    id?: string;
    /**
     * Gets or sets a value indicating whether this policy is default.
     * @type {boolean}
     * @memberof ScanPolicySettingItemApiModel
     */
    isDefault?: boolean;
    /**
     * Gets or sets a value indicating whether this scan policy is shared.
     * @type {boolean}
     * @memberof ScanPolicySettingItemApiModel
     */
    isShared?: boolean;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof ScanPolicySettingItemApiModel
     */
    name?: string;
    /**
     *
     * @type {ScanPolicyOptimizerOptions}
     * @memberof ScanPolicySettingItemApiModel
     */
    optimizerOptions?: ScanPolicyOptimizerOptions;
    /**
     * Gets or sets a value indicating whether this policy is account default.
     * @type {boolean}
     * @memberof ScanPolicySettingItemApiModel
     */
    isAccountDefault?: boolean;
    /**
     * Gets the name with sharing state.
     * @type {string}
     * @memberof ScanPolicySettingItemApiModel
     */
    readonly nameWithAccessModifier?: string;
}
/**
 * Check if a given object implements the ScanPolicySettingItemApiModel interface.
 */
export declare function instanceOfScanPolicySettingItemApiModel(value: object): boolean;
export declare function ScanPolicySettingItemApiModelFromJSON(json: any): ScanPolicySettingItemApiModel;
export declare function ScanPolicySettingItemApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanPolicySettingItemApiModel;
export declare function ScanPolicySettingItemApiModelToJSON(value?: ScanPolicySettingItemApiModel | null): any;
