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
    cVSS?: { [key: string]: object; };
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
    cVELIST?: { [key: string]: object; };
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
    dISCOVERY?: { [key: string]: object; };
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
export function instanceOfCustomTemplateContentModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function CustomTemplateContentModelFromJSON(json: any): CustomTemplateContentModel {
    return CustomTemplateContentModelFromJSONTyped(json, false);
}

export function CustomTemplateContentModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): CustomTemplateContentModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'cVSS': !exists(json, 'CVSS') ? undefined : json['CVSS'],
        'cATEGORY': !exists(json, 'CATEGORY') ? undefined : json['CATEGORY'],
        'cVELIST': !exists(json, 'CVE_LIST') ? undefined : json['CVE_LIST'],
        'pCIFLAG': !exists(json, 'PCI_FLAG') ? undefined : json['PCI_FLAG'],
        'dISCOVERY': !exists(json, 'DISCOVERY') ? undefined : json['DISCOVERY'],
        'pATCHABLE': !exists(json, 'PATCHABLE') ? undefined : json['PATCHABLE'],
        'vULNTYPE': !exists(json, 'VULN_TYPE') ? undefined : json['VULN_TYPE'],
    };
}

export function CustomTemplateContentModelToJSON(value?: CustomTemplateContentModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'CVSS': value.cVSS,
        'CATEGORY': value.cATEGORY,
        'CVE_LIST': value.cVELIST,
        'PCI_FLAG': value.pCIFLAG,
        'DISCOVERY': value.dISCOVERY,
        'PATCHABLE': value.pATCHABLE,
        'VULN_TYPE': value.vULNTYPE,
    };
}

