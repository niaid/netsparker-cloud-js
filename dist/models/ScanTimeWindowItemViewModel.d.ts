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
 * Represents a scan time window item.
 * @export
 * @interface ScanTimeWindowItemViewModel
 */
export interface ScanTimeWindowItemViewModel {
    /**
     * Gets or sets the day.
     * @type {string}
     * @memberof ScanTimeWindowItemViewModel
     */
    day?: ScanTimeWindowItemViewModelDayEnum;
    /**
     * Gets or sets the left side of the time range as minutes past from midnight.
     * @type {number}
     * @memberof ScanTimeWindowItemViewModel
     */
    from?: number;
    /**
     * Gets or sets a value indicating whether scanning is allowed or not.
     * @type {boolean}
     * @memberof ScanTimeWindowItemViewModel
     */
    scanningAllowed?: boolean;
    /**
     * Gets or sets the right side of the time range as minutes past from midnight.
     * @type {number}
     * @memberof ScanTimeWindowItemViewModel
     */
    to?: number;
}
/**
* @export
* @enum {string}
*/
export declare enum ScanTimeWindowItemViewModelDayEnum {
    Sunday = "Sunday",
    Monday = "Monday",
    Tuesday = "Tuesday",
    Wednesday = "Wednesday",
    Thursday = "Thursday",
    Friday = "Friday",
    Saturday = "Saturday"
}
/**
 * Check if a given object implements the ScanTimeWindowItemViewModel interface.
 */
export declare function instanceOfScanTimeWindowItemViewModel(value: object): boolean;
export declare function ScanTimeWindowItemViewModelFromJSON(json: any): ScanTimeWindowItemViewModel;
export declare function ScanTimeWindowItemViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanTimeWindowItemViewModel;
export declare function ScanTimeWindowItemViewModelToJSON(value?: ScanTimeWindowItemViewModel | null): any;
