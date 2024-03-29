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
 * @interface ReducedTeamDto
 */
export interface ReducedTeamDto {
    /**
     *
     * @type {string}
     * @memberof ReducedTeamDto
     */
    id?: string;
    /**
     *
     * @type {string}
     * @memberof ReducedTeamDto
     */
    name?: string;
}
/**
 * Check if a given object implements the ReducedTeamDto interface.
 */
export declare function instanceOfReducedTeamDto(value: object): boolean;
export declare function ReducedTeamDtoFromJSON(json: any): ReducedTeamDto;
export declare function ReducedTeamDtoFromJSONTyped(json: any, ignoreDiscriminator: boolean): ReducedTeamDto;
export declare function ReducedTeamDtoToJSON(value?: ReducedTeamDto | null): any;
