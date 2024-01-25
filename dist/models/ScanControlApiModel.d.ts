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
 * @interface ScanControlApiModel
 */
export interface ScanControlApiModel {
    /**
     *
     * @type {boolean}
     * @memberof ScanControlApiModel
     */
    isScansSuspended?: boolean;
}
/**
 * Check if a given object implements the ScanControlApiModel interface.
 */
export declare function instanceOfScanControlApiModel(value: object): boolean;
export declare function ScanControlApiModelFromJSON(json: any): ScanControlApiModel;
export declare function ScanControlApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanControlApiModel;
export declare function ScanControlApiModelToJSON(value?: ScanControlApiModel | null): any;
