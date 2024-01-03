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
/**
 * @export
 */
export const StartVerificationApiModelVerificationMethodEnum = {
    File: 'File',
    Tag: 'Tag',
    Dns: 'Dns',
    Email: 'Email'
};
/**
 * Check if a given object implements the StartVerificationApiModel interface.
 */
export function instanceOfStartVerificationApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "verificationMethod" in value;
    isInstance = isInstance && "websiteUrl" in value;
    return isInstance;
}
export function StartVerificationApiModelFromJSON(json) {
    return StartVerificationApiModelFromJSONTyped(json, false);
}
export function StartVerificationApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'verificationMethod': json['VerificationMethod'],
        'websiteUrl': json['WebsiteUrl'],
    };
}
export function StartVerificationApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'VerificationMethod': value.verificationMethod,
        'WebsiteUrl': value.websiteUrl,
    };
}
//# sourceMappingURL=StartVerificationApiModel.js.map