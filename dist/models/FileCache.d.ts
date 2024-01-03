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
 * @interface FileCache
 */
export interface FileCache {
    /**
     *
     * @type {string}
     * @memberof FileCache
     */
    key?: string;
    /**
     *
     * @type {string}
     * @memberof FileCache
     */
    fileName?: string;
    /**
     *
     * @type {number}
     * @memberof FileCache
     */
    id?: number;
    /**
     *
     * @type {string}
     * @memberof FileCache
     */
    accept?: string;
    /**
     *
     * @type {string}
     * @memberof FileCache
     */
    importerType?: FileCacheImporterTypeEnum;
    /**
     *
     * @type {string}
     * @memberof FileCache
     */
    uRL?: string;
    /**
     *
     * @type {string}
     * @memberof FileCache
     */
    apiURL?: string;
}
/**
 * @export
 */
export declare const FileCacheImporterTypeEnum: {
    readonly None: "None";
    readonly Fiddler: "Fiddler";
    readonly Burp: "Burp";
    readonly Swagger: "Swagger";
    readonly OwaspZap: "OwaspZap";
    readonly AspNet: "AspNet";
    readonly HttpArchive: "HttpArchive";
    readonly Wadl: "Wadl";
    readonly Wsdl: "Wsdl";
    readonly Postman: "Postman";
    readonly Netsparker: "Netsparker";
    readonly HttpRequestImporter: "HttpRequestImporter";
    readonly LinkImporter: "LinkImporter";
    readonly CsvImporter: "CsvImporter";
    readonly Iodocs: "Iodocs";
    readonly WordPress: "WordPress";
    readonly Raml: "Raml";
    readonly GraphQl: "GraphQl";
    readonly AcxXml: "AcxXml";
};
export type FileCacheImporterTypeEnum = typeof FileCacheImporterTypeEnum[keyof typeof FileCacheImporterTypeEnum];
/**
 * Check if a given object implements the FileCache interface.
 */
export declare function instanceOfFileCache(value: object): boolean;
export declare function FileCacheFromJSON(json: any): FileCache;
export declare function FileCacheFromJSONTyped(json: any, ignoreDiscriminator: boolean): FileCache;
export declare function FileCacheToJSON(value?: FileCache | null): any;
