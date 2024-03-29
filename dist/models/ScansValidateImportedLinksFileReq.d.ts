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
export declare function instanceOfScansValidateImportedLinksFileReq(value: object): boolean;
export declare function ScansValidateImportedLinksFileReqFromJSON(json: any): ScansValidateImportedLinksFileReq;
export declare function ScansValidateImportedLinksFileReqFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScansValidateImportedLinksFileReq;
export declare function ScansValidateImportedLinksFileReqToJSON(value?: ScansValidateImportedLinksFileReq | null): any;
