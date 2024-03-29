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
 * Represents credentials for Basic, NTML, Kerberos, Digest or Negotiate authentication.
 * @export
 * @interface BasicAuthenticationCredentialModel
 */
export interface BasicAuthenticationCredentialModel {
    /**
     * Gets or sets the type of the authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    authenticationType?: BasicAuthenticationCredentialModelAuthenticationTypeEnum;
    /**
     * Gets or sets the domain for basic authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    domain?: string;
    /**
     * Gets or sets the password for basic authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    password: string;
    /**
     * Gets or sets the URI prefix.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    uriPrefix: string;
    /**
     * Gets or sets the user name for basic authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    userName: string;
    /**
     * Gets or sets the URI prefix that not modified by user on client side.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    originalUriPrefix?: string;
    /**
     * Gets or sets the user name for basic authentication that not modified by user on client side.
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    originalUserName?: string;
    /**
     * Encrypted original password
     * @type {string}
     * @memberof BasicAuthenticationCredentialModel
     */
    originalPassword?: string;
    /**
     * Gets or sets a value indicating whether the placeholders is replaced with actual credentials.
     * @type {boolean}
     * @memberof BasicAuthenticationCredentialModel
     */
    isReplacedCredentials?: boolean;
}
/**
 * @export
 */
export declare const BasicAuthenticationCredentialModelAuthenticationTypeEnum: {
    readonly Basic: "Basic";
    readonly Ntlm: "Ntlm";
    readonly Kerberos: "Kerberos";
    readonly Digest: "Digest";
    readonly Negotiate: "Negotiate";
};
export type BasicAuthenticationCredentialModelAuthenticationTypeEnum = typeof BasicAuthenticationCredentialModelAuthenticationTypeEnum[keyof typeof BasicAuthenticationCredentialModelAuthenticationTypeEnum];
/**
 * Check if a given object implements the BasicAuthenticationCredentialModel interface.
 */
export declare function instanceOfBasicAuthenticationCredentialModel(value: object): boolean;
export declare function BasicAuthenticationCredentialModelFromJSON(json: any): BasicAuthenticationCredentialModel;
export declare function BasicAuthenticationCredentialModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BasicAuthenticationCredentialModel;
export declare function BasicAuthenticationCredentialModelToJSON(value?: BasicAuthenticationCredentialModel | null): any;
