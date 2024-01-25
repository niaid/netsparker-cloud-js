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
import type { SecurityCheckGroupModel } from './SecurityCheckGroupModel';
/**
 * Represents a model for carrying out security check groups.
 * @export
 * @interface SecurityCheckGroupParentModel
 */
export interface SecurityCheckGroupParentModel {
    /**
     *
     * @type {string}
     * @memberof SecurityCheckGroupParentModel
     */
    title?: string;
    /**
     *
     * @type {Array<SecurityCheckGroupModel>}
     * @memberof SecurityCheckGroupParentModel
     */
    securityCheckGroups?: Array<SecurityCheckGroupModel>;
}
/**
 * Check if a given object implements the SecurityCheckGroupParentModel interface.
 */
export declare function instanceOfSecurityCheckGroupParentModel(value: object): boolean;
export declare function SecurityCheckGroupParentModelFromJSON(json: any): SecurityCheckGroupParentModel;
export declare function SecurityCheckGroupParentModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): SecurityCheckGroupParentModel;
export declare function SecurityCheckGroupParentModelToJSON(value?: SecurityCheckGroupParentModel | null): any;
