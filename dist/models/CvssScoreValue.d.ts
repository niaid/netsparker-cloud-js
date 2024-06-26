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
 * @interface CvssScoreValue
 */
export interface CvssScoreValue {
    /**
     *
     * @type {string}
     * @memberof CvssScoreValue
     */
    readonly severity?: CvssScoreValueSeverityEnum;
    /**
     *
     * @type {number}
     * @memberof CvssScoreValue
     */
    readonly value?: number;
}
/**
 * @export
 */
export declare const CvssScoreValueSeverityEnum: {
    readonly None: "None";
    readonly Low: "Low";
    readonly Medium: "Medium";
    readonly High: "High";
    readonly Critical: "Critical";
};
export type CvssScoreValueSeverityEnum = typeof CvssScoreValueSeverityEnum[keyof typeof CvssScoreValueSeverityEnum];
/**
 * Check if a given object implements the CvssScoreValue interface.
 */
export declare function instanceOfCvssScoreValue(value: object): boolean;
export declare function CvssScoreValueFromJSON(json: any): CvssScoreValue;
export declare function CvssScoreValueFromJSONTyped(json: any, ignoreDiscriminator: boolean): CvssScoreValue;
export declare function CvssScoreValueToJSON(value?: Omit<CvssScoreValue, 'Severity' | 'Value'> | null): any;
