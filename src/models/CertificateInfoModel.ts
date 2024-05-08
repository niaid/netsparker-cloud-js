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

import { mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface CertificateInfoModel
 */
export interface CertificateInfoModel {
    /**
     * 
     * @type {string}
     * @memberof CertificateInfoModel
     */
    cN?: string;
    /**
     * 
     * @type {string}
     * @memberof CertificateInfoModel
     */
    expresionDate?: string;
    /**
     * 
     * @type {string}
     * @memberof CertificateInfoModel
     */
    thumbprint?: string;
}

/**
 * Check if a given object implements the CertificateInfoModel interface.
 */
export function instanceOfCertificateInfoModel(value: object): boolean {
    return true;
}

export function CertificateInfoModelFromJSON(json: any): CertificateInfoModel {
    return CertificateInfoModelFromJSONTyped(json, false);
}

export function CertificateInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): CertificateInfoModel {
    if (json == null) {
        return json;
    }
    return {
        
        'cN': json['CN'] == null ? undefined : json['CN'],
        'expresionDate': json['ExpresionDate'] == null ? undefined : json['ExpresionDate'],
        'thumbprint': json['Thumbprint'] == null ? undefined : json['Thumbprint'],
    };
}

export function CertificateInfoModelToJSON(value?: CertificateInfoModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'CN': value['cN'],
        'ExpresionDate': value['expresionDate'],
        'Thumbprint': value['thumbprint'],
    };
}

