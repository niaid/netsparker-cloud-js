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
 * @interface FreshserviceUser
 */
export interface FreshserviceUser {
    /**
     *
     * @type {string}
     * @memberof FreshserviceUser
     */
    email?: string;
    /**
     *
     * @type {number}
     * @memberof FreshserviceUser
     */
    id?: number;
    /**
     *
     * @type {string}
     * @memberof FreshserviceUser
     */
    name?: string;
}
/**
 * Check if a given object implements the FreshserviceUser interface.
 */
export declare function instanceOfFreshserviceUser(value: object): boolean;
export declare function FreshserviceUserFromJSON(json: any): FreshserviceUser;
export declare function FreshserviceUserFromJSONTyped(json: any, ignoreDiscriminator: boolean): FreshserviceUser;
export declare function FreshserviceUserToJSON(value?: FreshserviceUser | null): any;
