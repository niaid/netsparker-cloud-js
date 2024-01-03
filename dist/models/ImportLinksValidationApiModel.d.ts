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
 * @interface ImportLinksValidationApiModel
 */
export interface ImportLinksValidationApiModel {
    /**
     * Gets or sets the site url for import links.
     * @type {string}
     * @memberof ImportLinksValidationApiModel
     */
    siteUrl: string;
    /**
     * Gets or sets the the file import type.
     * @type {string}
     * @memberof ImportLinksValidationApiModel
     */
    importType?: ImportLinksValidationApiModelImportTypeEnum;
}
/**
* @export
* @enum {string}
*/
export declare enum ImportLinksValidationApiModelImportTypeEnum {
    None = "None",
    Fiddler = "Fiddler",
    Burp = "Burp",
    Swagger = "Swagger",
    OwaspZap = "OwaspZap",
    AspNet = "AspNet",
    HttpArchive = "HttpArchive",
    Wadl = "Wadl",
    Wsdl = "Wsdl",
    Postman = "Postman",
    InvictiSessionFile = "InvictiSessionFile",
    CsvImporter = "CsvImporter",
    Iodocs = "Iodocs",
    WordPress = "WordPress",
    Raml = "Raml",
    GraphQl = "GraphQl"
}
/**
 * Check if a given object implements the ImportLinksValidationApiModel interface.
 */
export declare function instanceOfImportLinksValidationApiModel(value: object): boolean;
export declare function ImportLinksValidationApiModelFromJSON(json: any): ImportLinksValidationApiModel;
export declare function ImportLinksValidationApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ImportLinksValidationApiModel;
export declare function ImportLinksValidationApiModelToJSON(value?: ImportLinksValidationApiModel | null): any;
