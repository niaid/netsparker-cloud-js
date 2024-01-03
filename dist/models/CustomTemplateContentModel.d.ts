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
 * Sentinel vulnerability template model.
 * @export
 * @interface CustomTemplateContentModel
 */
export interface CustomTemplateContentModel {
    /**
     * Gets or sets sentinel cvss.
     * @type {{ [key: string]: object; }}
     * @memberof CustomTemplateContentModel
     */
    cVSS?: {
        [key: string]: object;
    };
    /**
     * Gets or sets vulnerability category
     * @type {string}
     * @memberof CustomTemplateContentModel
     */
    cATEGORY?: string;
    /**
     * Gets or sets CveList
     * @type {{ [key: string]: object; }}
     * @memberof CustomTemplateContentModel
     */
    cVELIST?: {
        [key: string]: object;
    };
    /**
     * Gets or sets pci flag.
     * @type {string}
     * @memberof CustomTemplateContentModel
     */
    pCIFLAG?: string;
    /**
     * Gets or sets discovery
     * @type {{ [key: string]: object; }}
     * @memberof CustomTemplateContentModel
     */
    dISCOVERY?: {
        [key: string]: object;
    };
    /**
     * Gets or sets patchable
     * @type {string}
     * @memberof CustomTemplateContentModel
     */
    pATCHABLE?: string;
    /**
     * One of the following types: Vulnerability/Potential/Information Gathered
     * @type {string}
     * @memberof CustomTemplateContentModel
     */
    vULNTYPE?: string;
}
/**
 * Check if a given object implements the CustomTemplateContentModel interface.
 */
export declare function instanceOfCustomTemplateContentModel(value: object): boolean;
export declare function CustomTemplateContentModelFromJSON(json: any): CustomTemplateContentModel;
export declare function CustomTemplateContentModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): CustomTemplateContentModel;
export declare function CustomTemplateContentModelToJSON(value?: CustomTemplateContentModel | null): any;
