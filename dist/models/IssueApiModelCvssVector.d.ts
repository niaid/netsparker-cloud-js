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
import type { CvssMetricModel } from './CvssMetricModel';
/**
 * Gets the parsed cvss vector
 * @export
 * @interface IssueApiModelCvssVector
 */
export interface IssueApiModelCvssVector {
    /**
     *
     * @type {CvssMetricModel}
     * @memberof IssueApiModelCvssVector
     */
    base?: CvssMetricModel;
    /**
     *
     * @type {CvssMetricModel}
     * @memberof IssueApiModelCvssVector
     */
    temporal?: CvssMetricModel;
    /**
     *
     * @type {CvssMetricModel}
     * @memberof IssueApiModelCvssVector
     */
    environmental?: CvssMetricModel;
    /**
     *
     * @type {CvssMetricModel}
     * @memberof IssueApiModelCvssVector
     */
    threat?: CvssMetricModel;
    /**
     *
     * @type {CvssMetricModel}
     * @memberof IssueApiModelCvssVector
     */
    supplemental?: CvssMetricModel;
}
/**
 * Check if a given object implements the IssueApiModelCvssVector interface.
 */
export declare function instanceOfIssueApiModelCvssVector(value: object): boolean;
export declare function IssueApiModelCvssVectorFromJSON(json: any): IssueApiModelCvssVector;
export declare function IssueApiModelCvssVectorFromJSONTyped(json: any, ignoreDiscriminator: boolean): IssueApiModelCvssVector;
export declare function IssueApiModelCvssVectorToJSON(value?: IssueApiModelCvssVector | null): any;