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
 * @interface BasicAuthenticationCredentialApiModel
 */
export interface BasicAuthenticationCredentialApiModel {
    /**
     * Gets or sets the type of the authentication.
     * @type {string}
     * @memberof BasicAuthenticationCredentialApiModel
     */
    authenticationType?: BasicAuthenticationCredentialApiModelAuthenticationTypeEnum;
    /**
     * Gets or sets the domain or computer name that verifies the credentials.
     * @type {string}
     * @memberof BasicAuthenticationCredentialApiModel
     */
    domain?: string;
    /**
     * Gets or sets the password for the user name associated with the credentials.
     * @type {string}
     * @memberof BasicAuthenticationCredentialApiModel
     */
    password?: string;
    /**
     * Gets or sets the URI prefix.
     * @type {string}
     * @memberof BasicAuthenticationCredentialApiModel
     */
    uriPrefix?: string;
    /**
     * Gets or sets the user name associated with the credentials.
     * @type {string}
     * @memberof BasicAuthenticationCredentialApiModel
     */
    userName?: string;
}
/**
 * @export
 */
export declare const BasicAuthenticationCredentialApiModelAuthenticationTypeEnum: {
    readonly Basic: "Basic";
    readonly Ntlm: "Ntlm";
    readonly Kerberos: "Kerberos";
    readonly Digest: "Digest";
    readonly Negotiate: "Negotiate";
};
export type BasicAuthenticationCredentialApiModelAuthenticationTypeEnum = typeof BasicAuthenticationCredentialApiModelAuthenticationTypeEnum[keyof typeof BasicAuthenticationCredentialApiModelAuthenticationTypeEnum];
/**
 * Check if a given object implements the BasicAuthenticationCredentialApiModel interface.
 */
export declare function instanceOfBasicAuthenticationCredentialApiModel(value: object): boolean;
export declare function BasicAuthenticationCredentialApiModelFromJSON(json: any): BasicAuthenticationCredentialApiModel;
export declare function BasicAuthenticationCredentialApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BasicAuthenticationCredentialApiModel;
export declare function BasicAuthenticationCredentialApiModelToJSON(value?: BasicAuthenticationCredentialApiModel | null): any;