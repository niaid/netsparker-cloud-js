/* tslint:disable */
/* eslint-disable */
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

import { exists, mapValues } from '../runtime';
/**
 * Represents SSL/TLS settings.
 * @export
 * @interface SslTlsSettingModel
 */
export interface SslTlsSettingModel {
    /**
     * Gets or sets invalid certificate action for the external domains.
     * @type {string}
     * @memberof SslTlsSettingModel
     */
    externalDomainInvalidCertificateAction?: SslTlsSettingModelExternalDomainInvalidCertificateActionEnum;
    /**
     * Gets or sets a value indicating whether SSL v3 is enabled.
     * @type {boolean}
     * @memberof SslTlsSettingModel
     */
    ssl3Enabled?: boolean;
    /**
     * Gets or sets invalid certificate action for the target URL.
     * @type {string}
     * @memberof SslTlsSettingModel
     */
    targetUrlInvalidCertificateAction?: SslTlsSettingModelTargetUrlInvalidCertificateActionEnum;
    /**
     * Gets or sets a value indicating whether TLS 1.0 is enabled.
     * @type {boolean}
     * @memberof SslTlsSettingModel
     */
    tls10Enabled?: boolean;
    /**
     * Gets or sets a value indicating whether TLS 1.1 is enabled.
     * @type {boolean}
     * @memberof SslTlsSettingModel
     */
    tls11Enabled?: boolean;
    /**
     * Gets or sets a value indicating whether TLS 1.2 is enabled.
     * @type {boolean}
     * @memberof SslTlsSettingModel
     */
    tls12Enabled?: boolean;
    /**
     * Gets or sets a value indicating whether TLS 1.3 is enabled.
     * @type {boolean}
     * @memberof SslTlsSettingModel
     */
    tls13Enabled?: boolean;
}


/**
 * @export
 */
export const SslTlsSettingModelExternalDomainInvalidCertificateActionEnum = {
    Ignore: 'Ignore',
    Reject: 'Reject'
} as const;
export type SslTlsSettingModelExternalDomainInvalidCertificateActionEnum = typeof SslTlsSettingModelExternalDomainInvalidCertificateActionEnum[keyof typeof SslTlsSettingModelExternalDomainInvalidCertificateActionEnum];

/**
 * @export
 */
export const SslTlsSettingModelTargetUrlInvalidCertificateActionEnum = {
    Ignore: 'Ignore',
    Reject: 'Reject'
} as const;
export type SslTlsSettingModelTargetUrlInvalidCertificateActionEnum = typeof SslTlsSettingModelTargetUrlInvalidCertificateActionEnum[keyof typeof SslTlsSettingModelTargetUrlInvalidCertificateActionEnum];


/**
 * Check if a given object implements the SslTlsSettingModel interface.
 */
export function instanceOfSslTlsSettingModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function SslTlsSettingModelFromJSON(json: any): SslTlsSettingModel {
    return SslTlsSettingModelFromJSONTyped(json, false);
}

export function SslTlsSettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): SslTlsSettingModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'externalDomainInvalidCertificateAction': !exists(json, 'ExternalDomainInvalidCertificateAction') ? undefined : json['ExternalDomainInvalidCertificateAction'],
        'ssl3Enabled': !exists(json, 'Ssl3Enabled') ? undefined : json['Ssl3Enabled'],
        'targetUrlInvalidCertificateAction': !exists(json, 'TargetUrlInvalidCertificateAction') ? undefined : json['TargetUrlInvalidCertificateAction'],
        'tls10Enabled': !exists(json, 'Tls10Enabled') ? undefined : json['Tls10Enabled'],
        'tls11Enabled': !exists(json, 'Tls11Enabled') ? undefined : json['Tls11Enabled'],
        'tls12Enabled': !exists(json, 'Tls12Enabled') ? undefined : json['Tls12Enabled'],
        'tls13Enabled': !exists(json, 'Tls13Enabled') ? undefined : json['Tls13Enabled'],
    };
}

export function SslTlsSettingModelToJSON(value?: SslTlsSettingModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ExternalDomainInvalidCertificateAction': value.externalDomainInvalidCertificateAction,
        'Ssl3Enabled': value.ssl3Enabled,
        'TargetUrlInvalidCertificateAction': value.targetUrlInvalidCertificateAction,
        'Tls10Enabled': value.tls10Enabled,
        'Tls11Enabled': value.tls11Enabled,
        'Tls12Enabled': value.tls12Enabled,
        'Tls13Enabled': value.tls13Enabled,
    };
}
