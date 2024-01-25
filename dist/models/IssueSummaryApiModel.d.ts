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
import type { IssueSummaryListModel } from './IssueSummaryListModel';
/**
 *
 * @export
 * @interface IssueSummaryApiModel
 */
export interface IssueSummaryApiModel {
    /**
     * Gets or sets TargetUri
     * @type {string}
     * @memberof IssueSummaryApiModel
     */
    targetUri?: string;
    /**
     * Gets or sets Website Name
     * @type {string}
     * @memberof IssueSummaryApiModel
     */
    websiteName?: string;
    /**
     * Gets or sets WebsiteId
     * @type {string}
     * @memberof IssueSummaryApiModel
     */
    websiteId?: string;
    /**
     * Gets Last Successful Scan Date with user time zone.
     * @type {string}
     * @memberof IssueSummaryApiModel
     */
    readonly lastSuccessfulScanDate?: string;
    /**
     * Gets or sets Scan Group Id
     * @type {string}
     * @memberof IssueSummaryApiModel
     */
    scanGroupId?: string;
    /**
     * Gets or sets Scan Profile Name
     * @type {string}
     * @memberof IssueSummaryApiModel
     */
    scanProfileName?: string;
    /**
     * Gets or sets Scan Profile Tags
     * @type {Array<string>}
     * @memberof IssueSummaryApiModel
     */
    scanProfileTags?: Array<string>;
    /**
     * Gets or sets ScanTask Id
     * @type {string}
     * @memberof IssueSummaryApiModel
     */
    scanTaskId?: string;
    /**
     * Gets or sets Issue Summary Lists
     * @type {Array<IssueSummaryListModel>}
     * @memberof IssueSummaryApiModel
     */
    issueSummaryLists?: Array<IssueSummaryListModel>;
}
/**
 * Check if a given object implements the IssueSummaryApiModel interface.
 */
export declare function instanceOfIssueSummaryApiModel(value: object): boolean;
export declare function IssueSummaryApiModelFromJSON(json: any): IssueSummaryApiModel;
export declare function IssueSummaryApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): IssueSummaryApiModel;
export declare function IssueSummaryApiModelToJSON(value?: IssueSummaryApiModel | null): any;
