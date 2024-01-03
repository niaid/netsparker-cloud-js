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
 * Check if a given object implements the NewScanTaskWithProfileApiModel interface.
 */
export function instanceOfNewScanTaskWithProfileApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "profileName" in value;
    isInstance = isInstance && "targetUri" in value;
    return isInstance;
}
export function NewScanTaskWithProfileApiModelFromJSON(json) {
    return NewScanTaskWithProfileApiModelFromJSONTyped(json, false);
}
export function NewScanTaskWithProfileApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'profileName': json['ProfileName'],
        'targetUri': json['TargetUri'],
    };
}
export function NewScanTaskWithProfileApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'ProfileName': value.profileName,
        'TargetUri': value.targetUri,
    };
}
//# sourceMappingURL=NewScanTaskWithProfileApiModel.js.map