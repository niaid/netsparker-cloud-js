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
 * 
 * @export
 * @interface ScansValidateImportedLinksFileReq
 */
export interface ScansValidateImportedLinksFileReq {
    /**
     * Upload Imported Links File
     * @type {Blob}
     * @memberof ScansValidateImportedLinksFileReq
     */
    file: Blob;
}

/**
 * Check if a given object implements the ScansValidateImportedLinksFileReq interface.
 */
export function instanceOfScansValidateImportedLinksFileReq(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "file" in value;

    return isInstance;
}

export function ScansValidateImportedLinksFileReqFromJSON(json: any): ScansValidateImportedLinksFileReq {
    return ScansValidateImportedLinksFileReqFromJSONTyped(json, false);
}

export function ScansValidateImportedLinksFileReqFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScansValidateImportedLinksFileReq {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'file': json['File'],
    };
}

export function ScansValidateImportedLinksFileReqToJSON(value?: ScansValidateImportedLinksFileReq | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'File': value.file,
    };
}

