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
import { exists } from '../runtime';
/**
 * Check if a given object implements the CustomTemplateContentModel interface.
 */
export function instanceOfCustomTemplateContentModel(value) {
    let isInstance = true;
    return isInstance;
}
export function CustomTemplateContentModelFromJSON(json) {
    return CustomTemplateContentModelFromJSONTyped(json, false);
}
export function CustomTemplateContentModelFromJSONTyped(json, ignoreDiscriminator) {
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
export function CustomTemplateContentModelToJSON(value) {
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
//# sourceMappingURL=CustomTemplateContentModel.js.map