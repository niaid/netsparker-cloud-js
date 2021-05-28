"use strict";
/**
 * Netsparker Enterprise API
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
/**
* Represents a Form Authentication persona.
*/
class FormAuthenticationPersona {
    static getAttributeTypeMap() {
        return FormAuthenticationPersona.attributeTypeMap;
    }
}
FormAuthenticationPersona.discriminator = undefined;
FormAuthenticationPersona.attributeTypeMap = [
    {
        "name": "isActive",
        "baseName": "IsActive",
        "type": "boolean"
    },
    {
        "name": "password",
        "baseName": "Password",
        "type": "string"
    },
    {
        "name": "userName",
        "baseName": "UserName",
        "type": "string"
    },
    {
        "name": "otpType",
        "baseName": "OtpType",
        "type": "FormAuthenticationPersona.OtpTypeEnum"
    },
    {
        "name": "secretKey",
        "baseName": "SecretKey",
        "type": "string"
    },
    {
        "name": "digit",
        "baseName": "Digit",
        "type": "FormAuthenticationPersona.DigitEnum"
    },
    {
        "name": "period",
        "baseName": "Period",
        "type": "number"
    },
    {
        "name": "algorithm",
        "baseName": "Algorithm",
        "type": "FormAuthenticationPersona.AlgorithmEnum"
    },
    {
        "name": "formAuthType",
        "baseName": "FormAuthType",
        "type": "FormAuthenticationPersona.FormAuthTypeEnum"
    },
    {
        "name": "integrationId",
        "baseName": "IntegrationId",
        "type": "string"
    },
    {
        "name": "version",
        "baseName": "Version",
        "type": "FormAuthenticationPersona.VersionEnum"
    },
    {
        "name": "secretEngine",
        "baseName": "SecretEngine",
        "type": "string"
    },
    {
        "name": "secret",
        "baseName": "Secret",
        "type": "string"
    },
    {
        "name": "useStaticUsername",
        "baseName": "UseStaticUsername",
        "type": "boolean"
    },
    {
        "name": "staticUsername",
        "baseName": "StaticUsername",
        "type": "string"
    },
    {
        "name": "usernameKey",
        "baseName": "UsernameKey",
        "type": "string"
    },
    {
        "name": "passwordKey",
        "baseName": "PasswordKey",
        "type": "string"
    },
    {
        "name": "cyberArkUseStaticUsername",
        "baseName": "CyberArkUseStaticUsername",
        "type": "boolean"
    },
    {
        "name": "cyberArkStaticUsername",
        "baseName": "CyberArkStaticUsername",
        "type": "string"
    },
    {
        "name": "cyberArkUserNameQuery",
        "baseName": "CyberArkUserNameQuery",
        "type": "string"
    },
    {
        "name": "cyberArkPasswordQuery",
        "baseName": "CyberArkPasswordQuery",
        "type": "string"
    },
    {
        "name": "originalUserName",
        "baseName": "OriginalUserName",
        "type": "string"
    },
    {
        "name": "isReplacedCredentials",
        "baseName": "IsReplacedCredentials",
        "type": "boolean"
    }
];
exports.FormAuthenticationPersona = FormAuthenticationPersona;
(function (FormAuthenticationPersona) {
    let OtpTypeEnum;
    (function (OtpTypeEnum) {
        OtpTypeEnum[OtpTypeEnum["Totp"] = 'Totp'] = "Totp";
        OtpTypeEnum[OtpTypeEnum["Hotp"] = 'Hotp'] = "Hotp";
    })(OtpTypeEnum = FormAuthenticationPersona.OtpTypeEnum || (FormAuthenticationPersona.OtpTypeEnum = {}));
    let DigitEnum;
    (function (DigitEnum) {
        DigitEnum[DigitEnum["OtpDigit6"] = 'OtpDigit6'] = "OtpDigit6";
        DigitEnum[DigitEnum["OtpDigit7"] = 'OtpDigit7'] = "OtpDigit7";
        DigitEnum[DigitEnum["OtpDigit8"] = 'OtpDigit8'] = "OtpDigit8";
    })(DigitEnum = FormAuthenticationPersona.DigitEnum || (FormAuthenticationPersona.DigitEnum = {}));
    let AlgorithmEnum;
    (function (AlgorithmEnum) {
        AlgorithmEnum[AlgorithmEnum["Sha1"] = 'Sha1'] = "Sha1";
        AlgorithmEnum[AlgorithmEnum["Sha256"] = 'Sha256'] = "Sha256";
        AlgorithmEnum[AlgorithmEnum["Sha512"] = 'Sha512'] = "Sha512";
    })(AlgorithmEnum = FormAuthenticationPersona.AlgorithmEnum || (FormAuthenticationPersona.AlgorithmEnum = {}));
    let FormAuthTypeEnum;
    (function (FormAuthTypeEnum) {
        FormAuthTypeEnum[FormAuthTypeEnum["Manual"] = 'Manual'] = "Manual";
        FormAuthTypeEnum[FormAuthTypeEnum["Integration"] = 'Integration'] = "Integration";
    })(FormAuthTypeEnum = FormAuthenticationPersona.FormAuthTypeEnum || (FormAuthenticationPersona.FormAuthTypeEnum = {}));
    let VersionEnum;
    (function (VersionEnum) {
        VersionEnum[VersionEnum["V1"] = 'V1'] = "V1";
        VersionEnum[VersionEnum["V2"] = 'V2'] = "V2";
    })(VersionEnum = FormAuthenticationPersona.VersionEnum || (FormAuthenticationPersona.VersionEnum = {}));
})(FormAuthenticationPersona = exports.FormAuthenticationPersona || (exports.FormAuthenticationPersona = {}));
//# sourceMappingURL=formAuthenticationPersona.js.map