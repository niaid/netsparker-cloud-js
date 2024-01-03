"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthenticationProfileViewModelToJSON = exports.AuthenticationProfileViewModelFromJSONTyped = exports.AuthenticationProfileViewModelFromJSON = exports.instanceOfAuthenticationProfileViewModel = void 0;
const runtime_1 = require("../runtime");
const CustomScriptPageViewModel_1 = require("./CustomScriptPageViewModel");
/**
 * Check if a given object implements the AuthenticationProfileViewModel interface.
 */
function instanceOfAuthenticationProfileViewModel(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "triggeredUrl" in value;
    isInstance = isInstance && "loginUrl" in value;
    isInstance = isInstance && "customScripts" in value;
    return isInstance;
}
exports.instanceOfAuthenticationProfileViewModel = instanceOfAuthenticationProfileViewModel;
function AuthenticationProfileViewModelFromJSON(json) {
    return AuthenticationProfileViewModelFromJSONTyped(json, false);
}
exports.AuthenticationProfileViewModelFromJSON = AuthenticationProfileViewModelFromJSON;
function AuthenticationProfileViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'id') ? undefined : json['id'],
        'name': json['name'],
        'triggeredUrl': json['triggeredUrl'],
        'loginUrl': json['loginUrl'],
        'customScripts': (json['customScripts'].map(CustomScriptPageViewModel_1.CustomScriptPageViewModelFromJSON)),
    };
}
exports.AuthenticationProfileViewModelFromJSONTyped = AuthenticationProfileViewModelFromJSONTyped;
function AuthenticationProfileViewModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'id': value.id,
        'name': value.name,
        'triggeredUrl': value.triggeredUrl,
        'loginUrl': value.loginUrl,
        'customScripts': (value.customScripts.map(CustomScriptPageViewModel_1.CustomScriptPageViewModelToJSON)),
    };
}
exports.AuthenticationProfileViewModelToJSON = AuthenticationProfileViewModelToJSON;
//# sourceMappingURL=AuthenticationProfileViewModel.js.map