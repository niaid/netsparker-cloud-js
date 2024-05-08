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
import type { ApiFile } from './ApiFile';
/**
 * Represents a model for carrying out client certificate authentication settings.
 * @export
 * @interface ClientCertificateAuthenticationApiModel
 */
export interface ClientCertificateAuthenticationApiModel {
    /**
     *
     * @type {ApiFile}
     * @memberof ClientCertificateAuthenticationApiModel
     */
    file?: ApiFile;
    /**
     * Gets or sets a value indicating whether client certificate authentication is enabled.
     * @type {boolean}
     * @memberof ClientCertificateAuthenticationApiModel
     */
    isEnabled?: boolean;
    /**
     * Gets or sets the password for client certificate authentication.
     * @type {string}
     * @memberof ClientCertificateAuthenticationApiModel
     */
    password?: string;
}
/**
 * Check if a given object implements the ClientCertificateAuthenticationApiModel interface.
 */
export declare function instanceOfClientCertificateAuthenticationApiModel(value: object): boolean;
export declare function ClientCertificateAuthenticationApiModelFromJSON(json: any): ClientCertificateAuthenticationApiModel;
export declare function ClientCertificateAuthenticationApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ClientCertificateAuthenticationApiModel;
export declare function ClientCertificateAuthenticationApiModelToJSON(value?: ClientCertificateAuthenticationApiModel | null): any;
