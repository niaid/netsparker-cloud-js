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
 * @interface JiraPriorityMapping
 */
export interface JiraPriorityMapping {
    /**
     *
     * @type {string}
     * @memberof JiraPriorityMapping
     */
    priority?: string;
    /**
     *
     * @type {string}
     * @memberof JiraPriorityMapping
     */
    icSeverity?: JiraPriorityMappingIcSeverityEnum;
}
/**
 * @export
 */
export declare const JiraPriorityMappingIcSeverityEnum: {
    readonly BestPractice: "BestPractice";
    readonly Information: "Information";
    readonly Low: "Low";
    readonly Medium: "Medium";
    readonly High: "High";
    readonly Critical: "Critical";
};
export type JiraPriorityMappingIcSeverityEnum = typeof JiraPriorityMappingIcSeverityEnum[keyof typeof JiraPriorityMappingIcSeverityEnum];
/**
 * Check if a given object implements the JiraPriorityMapping interface.
 */
export declare function instanceOfJiraPriorityMapping(value: object): boolean;
export declare function JiraPriorityMappingFromJSON(json: any): JiraPriorityMapping;
export declare function JiraPriorityMappingFromJSONTyped(json: any, ignoreDiscriminator: boolean): JiraPriorityMapping;
export declare function JiraPriorityMappingToJSON(value?: JiraPriorityMapping | null): any;
