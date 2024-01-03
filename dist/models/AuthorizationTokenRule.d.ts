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
 * @interface AuthorizationTokenRule
 */
export interface AuthorizationTokenRule {
    /**
     * Gets or sets the source URL.
     * @type {string}
     * @memberof AuthorizationTokenRule
     */
    source?: string;
    /**
     * Gets or sets the target URL.
     * @type {string}
     * @memberof AuthorizationTokenRule
     */
    destination?: string;
}
/**
 * Check if a given object implements the AuthorizationTokenRule interface.
 */
export declare function instanceOfAuthorizationTokenRule(value: object): boolean;
export declare function AuthorizationTokenRuleFromJSON(json: any): AuthorizationTokenRule;
export declare function AuthorizationTokenRuleFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuthorizationTokenRule;
export declare function AuthorizationTokenRuleToJSON(value?: AuthorizationTokenRule | null): any;
