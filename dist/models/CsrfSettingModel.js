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
 * Check if a given object implements the CsrfSettingModel interface.
 */
export function instanceOfCsrfSettingModel(value) {
    let isInstance = true;
    return isInstance;
}
export function CsrfSettingModelFromJSON(json) {
    return CsrfSettingModelFromJSONTyped(json, false);
}
export function CsrfSettingModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'captchaIndicators': !exists(json, 'CaptchaIndicators') ? undefined : json['CaptchaIndicators'],
        'loginFormValues': !exists(json, 'LoginFormValues') ? undefined : json['LoginFormValues'],
        'nonFormValues': !exists(json, 'NonFormValues') ? undefined : json['NonFormValues'],
        'nonInputValues': !exists(json, 'NonInputValues') ? undefined : json['NonInputValues'],
        'userNameInputs': !exists(json, 'UserNameInputs') ? undefined : json['UserNameInputs'],
        'authenticatedPagesCheck': !exists(json, 'AuthenticatedPagesCheck') ? undefined : json['AuthenticatedPagesCheck'],
    };
}
export function CsrfSettingModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'CaptchaIndicators': value.captchaIndicators,
        'LoginFormValues': value.loginFormValues,
        'NonFormValues': value.nonFormValues,
        'NonInputValues': value.nonInputValues,
        'UserNameInputs': value.userNameInputs,
        'AuthenticatedPagesCheck': value.authenticatedPagesCheck,
    };
}
//# sourceMappingURL=CsrfSettingModel.js.map