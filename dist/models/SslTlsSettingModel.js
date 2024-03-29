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
exports.SslTlsSettingModelToJSON = exports.SslTlsSettingModelFromJSONTyped = exports.SslTlsSettingModelFromJSON = exports.instanceOfSslTlsSettingModel = exports.SslTlsSettingModelTargetUrlInvalidCertificateActionEnum = exports.SslTlsSettingModelExternalDomainInvalidCertificateActionEnum = void 0;
const runtime_1 = require("../runtime");
/**
 * @export
 */
exports.SslTlsSettingModelExternalDomainInvalidCertificateActionEnum = {
    Ignore: 'Ignore',
    Reject: 'Reject'
};
/**
 * @export
 */
exports.SslTlsSettingModelTargetUrlInvalidCertificateActionEnum = {
    Ignore: 'Ignore',
    Reject: 'Reject'
};
/**
 * Check if a given object implements the SslTlsSettingModel interface.
 */
function instanceOfSslTlsSettingModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfSslTlsSettingModel = instanceOfSslTlsSettingModel;
function SslTlsSettingModelFromJSON(json) {
    return SslTlsSettingModelFromJSONTyped(json, false);
}
exports.SslTlsSettingModelFromJSON = SslTlsSettingModelFromJSON;
function SslTlsSettingModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'externalDomainInvalidCertificateAction': !(0, runtime_1.exists)(json, 'ExternalDomainInvalidCertificateAction') ? undefined : json['ExternalDomainInvalidCertificateAction'],
        'ssl3Enabled': !(0, runtime_1.exists)(json, 'Ssl3Enabled') ? undefined : json['Ssl3Enabled'],
        'targetUrlInvalidCertificateAction': !(0, runtime_1.exists)(json, 'TargetUrlInvalidCertificateAction') ? undefined : json['TargetUrlInvalidCertificateAction'],
        'tls10Enabled': !(0, runtime_1.exists)(json, 'Tls10Enabled') ? undefined : json['Tls10Enabled'],
        'tls11Enabled': !(0, runtime_1.exists)(json, 'Tls11Enabled') ? undefined : json['Tls11Enabled'],
        'tls12Enabled': !(0, runtime_1.exists)(json, 'Tls12Enabled') ? undefined : json['Tls12Enabled'],
        'tls13Enabled': !(0, runtime_1.exists)(json, 'Tls13Enabled') ? undefined : json['Tls13Enabled'],
    };
}
exports.SslTlsSettingModelFromJSONTyped = SslTlsSettingModelFromJSONTyped;
function SslTlsSettingModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'ExternalDomainInvalidCertificateAction': value.externalDomainInvalidCertificateAction,
        'Ssl3Enabled': value.ssl3Enabled,
        'TargetUrlInvalidCertificateAction': value.targetUrlInvalidCertificateAction,
        'Tls10Enabled': value.tls10Enabled,
        'Tls11Enabled': value.tls11Enabled,
        'Tls12Enabled': value.tls12Enabled,
        'Tls13Enabled': value.tls13Enabled,
    };
}
exports.SslTlsSettingModelToJSON = SslTlsSettingModelToJSON;
//# sourceMappingURL=SslTlsSettingModel.js.map