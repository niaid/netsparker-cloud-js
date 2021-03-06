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
exports.NewScheduledScanApiModel = void 0;
/**
* Contains properties that required to start scheduled scan.
*/
class NewScheduledScanApiModel {
    static getAttributeTypeMap() {
        return NewScheduledScanApiModel.attributeTypeMap;
    }
}
exports.NewScheduledScanApiModel = NewScheduledScanApiModel;
NewScheduledScanApiModel.discriminator = undefined;
NewScheduledScanApiModel.attributeTypeMap = [
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "nextExecutionTime",
        "baseName": "NextExecutionTime",
        "type": "string"
    },
    {
        "name": "scheduleRunType",
        "baseName": "ScheduleRunType",
        "type": "NewScheduledScanApiModel.ScheduleRunTypeEnum"
    },
    {
        "name": "customRecurrence",
        "baseName": "CustomRecurrence",
        "type": "ScheduledScanRecurrenceApiModel"
    },
    {
        "name": "targetUri",
        "baseName": "TargetUri",
        "type": "string"
    },
    {
        "name": "additionalWebsites",
        "baseName": "AdditionalWebsites",
        "type": "Array<AdditionalWebsiteModel>"
    },
    {
        "name": "basicAuthenticationApiModel",
        "baseName": "BasicAuthenticationApiModel",
        "type": "BasicAuthenticationSettingModel"
    },
    {
        "name": "clientCertificateAuthenticationSetting",
        "baseName": "ClientCertificateAuthenticationSetting",
        "type": "ClientCertificateAuthenticationApiModel"
    },
    {
        "name": "cookies",
        "baseName": "Cookies",
        "type": "string"
    },
    {
        "name": "crawlAndAttack",
        "baseName": "CrawlAndAttack",
        "type": "boolean"
    },
    {
        "name": "enableHeuristicChecksInCustomUrlRewrite",
        "baseName": "EnableHeuristicChecksInCustomUrlRewrite",
        "type": "boolean"
    },
    {
        "name": "excludedLinks",
        "baseName": "ExcludedLinks",
        "type": "Array<ExcludedLinkModel>"
    },
    {
        "name": "excludedUsageTrackers",
        "baseName": "ExcludedUsageTrackers",
        "type": "Array<ExcludedUsageTrackerModel>"
    },
    {
        "name": "disallowedHttpMethods",
        "baseName": "DisallowedHttpMethods",
        "type": "Array<NewScheduledScanApiModel.DisallowedHttpMethodsEnum>"
    },
    {
        "name": "excludeLinks",
        "baseName": "ExcludeLinks",
        "type": "boolean"
    },
    {
        "name": "excludeAuthenticationPages",
        "baseName": "ExcludeAuthenticationPages",
        "type": "boolean"
    },
    {
        "name": "findAndFollowNewLinks",
        "baseName": "FindAndFollowNewLinks",
        "type": "boolean"
    },
    {
        "name": "formAuthenticationSettingModel",
        "baseName": "FormAuthenticationSettingModel",
        "type": "FormAuthenticationSettingModel"
    },
    {
        "name": "headerAuthentication",
        "baseName": "HeaderAuthentication",
        "type": "HeaderAuthenticationModel"
    },
    {
        "name": "sharkSetting",
        "baseName": "SharkSetting",
        "type": "SharkModel"
    },
    {
        "name": "authenticationProfileOption",
        "baseName": "AuthenticationProfileOption",
        "type": "NewScheduledScanApiModel.AuthenticationProfileOptionEnum"
    },
    {
        "name": "authenticationProfileId",
        "baseName": "AuthenticationProfileId",
        "type": "string"
    },
    {
        "name": "importedLinks",
        "baseName": "ImportedLinks",
        "type": "Array<string>"
    },
    {
        "name": "importedFiles",
        "baseName": "ImportedFiles",
        "type": "Array<ApiFileModel>"
    },
    {
        "name": "isMaxScanDurationEnabled",
        "baseName": "IsMaxScanDurationEnabled",
        "type": "boolean"
    },
    {
        "name": "maxDynamicSignatures",
        "baseName": "MaxDynamicSignatures",
        "type": "number"
    },
    {
        "name": "maxScanDuration",
        "baseName": "MaxScanDuration",
        "type": "number"
    },
    {
        "name": "policyId",
        "baseName": "PolicyId",
        "type": "string"
    },
    {
        "name": "reportPolicyId",
        "baseName": "ReportPolicyId",
        "type": "string"
    },
    {
        "name": "scope",
        "baseName": "Scope",
        "type": "NewScheduledScanApiModel.ScopeEnum"
    },
    {
        "name": "subPathMaxDynamicSignatures",
        "baseName": "SubPathMaxDynamicSignatures",
        "type": "number"
    },
    {
        "name": "timeWindow",
        "baseName": "TimeWindow",
        "type": "ScanTimeWindowModel"
    },
    {
        "name": "urlRewriteAnalyzableExtensions",
        "baseName": "UrlRewriteAnalyzableExtensions",
        "type": "string"
    },
    {
        "name": "urlRewriteBlockSeparators",
        "baseName": "UrlRewriteBlockSeparators",
        "type": "string"
    },
    {
        "name": "urlRewriteMode",
        "baseName": "UrlRewriteMode",
        "type": "NewScheduledScanApiModel.UrlRewriteModeEnum"
    },
    {
        "name": "urlRewriteRules",
        "baseName": "UrlRewriteRules",
        "type": "Array<UrlRewriteRuleModel>"
    },
    {
        "name": "preRequestScriptSetting",
        "baseName": "PreRequestScriptSetting",
        "type": "PreRequestScriptSettingModel"
    },
    {
        "name": "doNotDifferentiateProtocols",
        "baseName": "DoNotDifferentiateProtocols",
        "type": "boolean"
    },
    {
        "name": "urlRewriteExcludedLinks",
        "baseName": "UrlRewriteExcludedLinks",
        "type": "Array<UrlRewriteExcludedPathModel>"
    },
    {
        "name": "oAuth2SettingModel",
        "baseName": "OAuth2SettingModel",
        "type": "OAuth2SettingApiModel"
    },
    {
        "name": "enablePciScanTask",
        "baseName": "EnablePciScanTask",
        "type": "boolean"
    }
];
(function (NewScheduledScanApiModel) {
    let ScheduleRunTypeEnum;
    (function (ScheduleRunTypeEnum) {
        ScheduleRunTypeEnum[ScheduleRunTypeEnum["Once"] = 'Once'] = "Once";
        ScheduleRunTypeEnum[ScheduleRunTypeEnum["Daily"] = 'Daily'] = "Daily";
        ScheduleRunTypeEnum[ScheduleRunTypeEnum["Weekly"] = 'Weekly'] = "Weekly";
        ScheduleRunTypeEnum[ScheduleRunTypeEnum["Monthly"] = 'Monthly'] = "Monthly";
        ScheduleRunTypeEnum[ScheduleRunTypeEnum["Quarterly"] = 'Quarterly'] = "Quarterly";
        ScheduleRunTypeEnum[ScheduleRunTypeEnum["Biannually"] = 'Biannually'] = "Biannually";
        ScheduleRunTypeEnum[ScheduleRunTypeEnum["Yearly"] = 'Yearly'] = "Yearly";
        ScheduleRunTypeEnum[ScheduleRunTypeEnum["Custom"] = 'Custom'] = "Custom";
    })(ScheduleRunTypeEnum = NewScheduledScanApiModel.ScheduleRunTypeEnum || (NewScheduledScanApiModel.ScheduleRunTypeEnum = {}));
    let DisallowedHttpMethodsEnum;
    (function (DisallowedHttpMethodsEnum) {
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Get"] = 'GET'] = "Get";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Post"] = 'POST'] = "Post";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Connect"] = 'CONNECT'] = "Connect";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Head"] = 'HEAD'] = "Head";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Trace"] = 'TRACE'] = "Trace";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Debug"] = 'DEBUG'] = "Debug";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Track"] = 'TRACK'] = "Track";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Put"] = 'PUT'] = "Put";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Options"] = 'OPTIONS'] = "Options";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Delete"] = 'DELETE'] = "Delete";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Link"] = 'LINK'] = "Link";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Unlink"] = 'UNLINK'] = "Unlink";
        DisallowedHttpMethodsEnum[DisallowedHttpMethodsEnum["Patch"] = 'PATCH'] = "Patch";
    })(DisallowedHttpMethodsEnum = NewScheduledScanApiModel.DisallowedHttpMethodsEnum || (NewScheduledScanApiModel.DisallowedHttpMethodsEnum = {}));
    let AuthenticationProfileOptionEnum;
    (function (AuthenticationProfileOptionEnum) {
        AuthenticationProfileOptionEnum[AuthenticationProfileOptionEnum["DontUse"] = 'DontUse'] = "DontUse";
        AuthenticationProfileOptionEnum[AuthenticationProfileOptionEnum["UseMatchedProfile"] = 'UseMatchedProfile'] = "UseMatchedProfile";
        AuthenticationProfileOptionEnum[AuthenticationProfileOptionEnum["SelectedProfile"] = 'SelectedProfile'] = "SelectedProfile";
    })(AuthenticationProfileOptionEnum = NewScheduledScanApiModel.AuthenticationProfileOptionEnum || (NewScheduledScanApiModel.AuthenticationProfileOptionEnum = {}));
    let ScopeEnum;
    (function (ScopeEnum) {
        ScopeEnum[ScopeEnum["EnteredPathAndBelow"] = 'EnteredPathAndBelow'] = "EnteredPathAndBelow";
        ScopeEnum[ScopeEnum["OnlyEnteredUrl"] = 'OnlyEnteredUrl'] = "OnlyEnteredUrl";
        ScopeEnum[ScopeEnum["WholeDomain"] = 'WholeDomain'] = "WholeDomain";
    })(ScopeEnum = NewScheduledScanApiModel.ScopeEnum || (NewScheduledScanApiModel.ScopeEnum = {}));
    let UrlRewriteModeEnum;
    (function (UrlRewriteModeEnum) {
        UrlRewriteModeEnum[UrlRewriteModeEnum["None"] = 'None'] = "None";
        UrlRewriteModeEnum[UrlRewriteModeEnum["Heuristic"] = 'Heuristic'] = "Heuristic";
        UrlRewriteModeEnum[UrlRewriteModeEnum["Custom"] = 'Custom'] = "Custom";
    })(UrlRewriteModeEnum = NewScheduledScanApiModel.UrlRewriteModeEnum || (NewScheduledScanApiModel.UrlRewriteModeEnum = {}));
})(NewScheduledScanApiModel = exports.NewScheduledScanApiModel || (exports.NewScheduledScanApiModel = {}));
//# sourceMappingURL=newScheduledScanApiModel.js.map