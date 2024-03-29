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
 * @interface ScanTimeWindowItemModel
 */
export interface ScanTimeWindowItemModel {
    /**
     *
     * @type {string}
     * @memberof ScanTimeWindowItemModel
     */
    day?: ScanTimeWindowItemModelDayEnum;
    /**
     *
     * @type {string}
     * @memberof ScanTimeWindowItemModel
     */
    from?: string;
    /**
     *
     * @type {boolean}
     * @memberof ScanTimeWindowItemModel
     */
    scanningAllowed?: boolean;
    /**
     *
     * @type {string}
     * @memberof ScanTimeWindowItemModel
     */
    to?: string;
}
/**
 * @export
 */
export declare const ScanTimeWindowItemModelDayEnum: {
    readonly Sunday: "Sunday";
    readonly Monday: "Monday";
    readonly Tuesday: "Tuesday";
    readonly Wednesday: "Wednesday";
    readonly Thursday: "Thursday";
    readonly Friday: "Friday";
    readonly Saturday: "Saturday";
};
export type ScanTimeWindowItemModelDayEnum = typeof ScanTimeWindowItemModelDayEnum[keyof typeof ScanTimeWindowItemModelDayEnum];
/**
 * Check if a given object implements the ScanTimeWindowItemModel interface.
 */
export declare function instanceOfScanTimeWindowItemModel(value: object): boolean;
export declare function ScanTimeWindowItemModelFromJSON(json: any): ScanTimeWindowItemModel;
export declare function ScanTimeWindowItemModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanTimeWindowItemModel;
export declare function ScanTimeWindowItemModelToJSON(value?: ScanTimeWindowItemModel | null): any;
