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
import type { HeaderAuthenticationModel } from './HeaderAuthenticationModel';
import type { PreRequestScriptSettingModel } from './PreRequestScriptSettingModel';
import type { TagViewModel } from './TagViewModel';
import type { FormAuthenticationSettingModel } from './FormAuthenticationSettingModel';
import type { ScheduledScanUpdateViewModel } from './ScheduledScanUpdateViewModel';
import type { ScheduledScanRecurrenceViewModel } from './ScheduledScanRecurrenceViewModel';
import type { BusinessLogicRecorderSettingModel } from './BusinessLogicRecorderSettingModel';
import type { ClientCertificateAuthenticationViewModel } from './ClientCertificateAuthenticationViewModel';
import type { OAuth2SettingModel } from './OAuth2SettingModel';
import type { AgentSelectionModel } from './AgentSelectionModel';
import type { BasicAuthenticationSettingModel } from './BasicAuthenticationSettingModel';
import type { UrlRewriteSetting } from './UrlRewriteSetting';
import type { SharkModel } from './SharkModel';
import type { AdditionalWebsitesSettingModel } from './AdditionalWebsitesSettingModel';
import type { ImportedLinksApiModel } from './ImportedLinksApiModel';
import type { ScanTimeWindowModel } from './ScanTimeWindowModel';
import type { ScopeSetting } from './ScopeSetting';
/**
 *
 * @export
 * @interface ScheduledScanApiModel
 */
export interface ScheduledScanApiModel {
    /**
     *
     * @type {ImportedLinksApiModel}
     * @memberof ScheduledScanApiModel
     */
    importedLinks?: ImportedLinksApiModel;
    /**
     * Gets or sets the last executed scan task identifier.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    lastExecutedScanTaskId?: string;
    /**
     * Gets or sets the last execution error.
     * @type {number}
     * @memberof ScheduledScanApiModel
     */
    lastExecutionError?: number;
    /**
     * Gets or sets the last execution status. If value is not {Invicti.Enterprise.Scans.ScanLaunchStatus.Ok}, specifies error type of
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    lastExecutionStatus?: ScheduledScanApiModelLastExecutionStatusEnum;
    /**
     *
     * @type {ScanTimeWindowModel}
     * @memberof ScheduledScanApiModel
     */
    timeWindow?: ScanTimeWindowModel;
    /**
     * Gets or sets the identifier.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    id?: string;
    /**
     * Gets or sets the how many times a scheduled scan triggered.
     * @type {number}
     * @memberof ScheduledScanApiModel
     */
    occurencesCount?: number;
    /**
     * Gets or sets a value indicating whether scheduled scan is disabled.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    disabled?: boolean;
    /**
     * Gets or sets a value indicating whether scheduling enabled.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    enableScheduling?: boolean;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    name?: string;
    /**
     * Gets or sets the next execution time.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    nextExecutionTime?: string;
    /**
     * Gets or sets scan group id
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    scanGroupId?: string;
    /**
     * Gets or sets scan type.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    scanType?: ScheduledScanApiModelScanTypeEnum;
    /**
     * Gets or sets the run interval of scheduled scan.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    scheduleRunType?: ScheduledScanApiModelScheduleRunTypeEnum;
    /**
     *
     * @type {ScheduledScanRecurrenceViewModel}
     * @memberof ScheduledScanApiModel
     */
    customRecurrence?: ScheduledScanRecurrenceViewModel;
    /**
     * The Template Type
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    readonly customScriptTemplateType?: ScheduledScanApiModelCustomScriptTemplateTypeEnum;
    /**
     * Gets or sets whether is target URL required.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    readonly isTargetUrlRequired?: boolean;
    /**
     * Get or set the is generate optimize css or not.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    isGenerateOptimizedCss?: boolean;
    /**
     *
     * @type {Array<TagViewModel>}
     * @memberof ScheduledScanApiModel
     */
    accountTags?: Array<TagViewModel>;
    /**
     *
     * @type {Array<string>}
     * @memberof ScheduledScanApiModel
     */
    entityCurrentTags?: Array<string>;
    /**
     * Gets or sets scheduledTaskNames
     * @type {Array<ScheduledScanUpdateViewModel>}
     * @memberof ScheduledScanApiModel
     */
    scheduledTaskNames?: Array<ScheduledScanUpdateViewModel>;
    /**
     * Gets or sets the foreign key reference to the related Launch Setting Id.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    launchSettingId?: string;
    /**
     *
     * @type {AdditionalWebsitesSettingModel}
     * @memberof ScheduledScanApiModel
     */
    additionalWebsites?: AdditionalWebsitesSettingModel;
    /**
     * Gets or sets the agent group identifier
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    agentGroupId?: string;
    /**
     * Gets or sets the agent identifier.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    agentId?: string;
    /**
     *
     * @type {BasicAuthenticationSettingModel}
     * @memberof ScheduledScanApiModel
     */
    basicAuthenticationSetting?: BasicAuthenticationSettingModel;
    /**
     * Gets or sets the can edit.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    readonly canEdit?: boolean;
    /**
     *
     * @type {ClientCertificateAuthenticationViewModel}
     * @memberof ScheduledScanApiModel
     */
    clientCertificateAuthentication?: ClientCertificateAuthenticationViewModel;
    /**
     * Gets or sets the cookies.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    cookies?: string;
    /**
     * Gets or sets the comments.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    comments?: string;
    /**
     * Gets or sets a value indicating whether parallel attacker is enabled.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    crawlAndAttack?: boolean;
    /**
     * Gets or sets the type of the create.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    createType?: ScheduledScanApiModelCreateTypeEnum;
    /**
     * Gets or sets the type of the authentication profile.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    authenticationProfileOption?: string;
    /**
     * Gets or sets the type of the authentication profile name.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    authenticationProfileName?: string;
    /**
     * Gets or sets a value indicating whether automatic crawling is enabled.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    findAndFollowNewLinks?: boolean;
    /**
     *
     * @type {FormAuthenticationSettingModel}
     * @memberof ScheduledScanApiModel
     */
    formAuthenticationSetting?: FormAuthenticationSettingModel;
    /**
     *
     * @type {HeaderAuthenticationModel}
     * @memberof ScheduledScanApiModel
     */
    headerAuthentication?: HeaderAuthenticationModel;
    /**
     *
     * @type {SharkModel}
     * @memberof ScheduledScanApiModel
     */
    shark?: SharkModel;
    /**
     * Gets or sets a value indicating whether max scan duration is enabled.
     * This is only used for scheduled group scan and regular group scan.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    isMaxScanDurationEnabled?: boolean;
    /**
     * Gets or sets a value indicating whether this instance is primary.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    isPrimary?: boolean;
    /**
     * Gets or sets a value indicating whether this instance is shared.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    isShared?: boolean;
    /**
     * Gets or sets the maximum duration of the scan in hours.
     * @type {number}
     * @memberof ScheduledScanApiModel
     */
    maxScanDuration?: number;
    /**
     * Gets or sets the scan policy identifier. This property is required if CreateType is Website
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    policyId?: string;
    /**
     * Gets or sets scan policy name
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    policyName?: string;
    /**
     * Gets or sets the profile identifier.
     * Keep this up-to-date with the UniqueProfileNameAttribute.ProfileIdPropertyName const
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    profileId?: string;
    /**
     * Gets or sets a name for this instance.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    profileName?: string;
    /**
     * Gets or sets the report policy identifier. This property is required if CreateType is Website
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    reportPolicyId?: string;
    /**
     * Gets or sets report policy name
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    reportPolicyName?: string;
    /**
     * Gets or sets the save scan profile.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    saveScanProfile?: boolean;
    /**
     *
     * @type {ScopeSetting}
     * @memberof ScheduledScanApiModel
     */
    scopeSetting?: ScopeSetting;
    /**
     * Gets or sets the agent selections for the websites that use custom agent. This property is needed for Gorup Scans.
     * @type {Array<AgentSelectionModel>}
     * @memberof ScheduledScanApiModel
     */
    selectedAgents?: Array<AgentSelectionModel>;
    /**
     * Gets or sets the selected scan profile identifier.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    selectedScanProfileId?: string;
    /**
     * Gets or sets the name of the selected scan profile.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    selectedScanProfileName?: string;
    /**
     * Gets or sets the target website URL. This property is required if CreateType is Website
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    targetUrl?: string;
    /**
     * Gets or sets the target website's Descripition. This property is used if CreateType is Website
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    description?: string;
    /**
     *
     * @type {UrlRewriteSetting}
     * @memberof ScheduledScanApiModel
     */
    urlRewriteSetting?: UrlRewriteSetting;
    /**
     *
     * @type {PreRequestScriptSettingModel}
     * @memberof ScheduledScanApiModel
     */
    preRequestScriptSetting?: PreRequestScriptSettingModel;
    /**
     * Gets or sets the user identifier.
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    userId?: string;
    /**
     * Gets or sets the website group identifier. This property is required if CreateType is WebsiteGroup
     * @type {string}
     * @memberof ScheduledScanApiModel
     */
    websiteGroupId?: string;
    /**
     * Defines whether a pci scan task going to be started.
     * @type {boolean}
     * @memberof ScheduledScanApiModel
     */
    enablePciScanTask?: boolean;
    /**
     *
     * @type {OAuth2SettingModel}
     * @memberof ScheduledScanApiModel
     */
    oAuth2Setting?: OAuth2SettingModel;
    /**
     *
     * @type {BusinessLogicRecorderSettingModel}
     * @memberof ScheduledScanApiModel
     */
    businessLogicRecorder?: BusinessLogicRecorderSettingModel;
}
/**
 * @export
 */
export declare const ScheduledScanApiModelLastExecutionStatusEnum: {
    readonly Ok: "Ok";
    readonly LicenseError: "LicenseError";
};
export type ScheduledScanApiModelLastExecutionStatusEnum = typeof ScheduledScanApiModelLastExecutionStatusEnum[keyof typeof ScheduledScanApiModelLastExecutionStatusEnum];
/**
 * @export
 */
export declare const ScheduledScanApiModelScanTypeEnum: {
    readonly Full: "Full";
    readonly Retest: "Retest";
    readonly Incremental: "Incremental";
};
export type ScheduledScanApiModelScanTypeEnum = typeof ScheduledScanApiModelScanTypeEnum[keyof typeof ScheduledScanApiModelScanTypeEnum];
/**
 * @export
 */
export declare const ScheduledScanApiModelScheduleRunTypeEnum: {
    readonly Once: "Once";
    readonly Daily: "Daily";
    readonly Weekly: "Weekly";
    readonly Monthly: "Monthly";
    readonly Quarterly: "Quarterly";
    readonly Biannually: "Biannually";
    readonly Yearly: "Yearly";
    readonly Custom: "Custom";
};
export type ScheduledScanApiModelScheduleRunTypeEnum = typeof ScheduledScanApiModelScheduleRunTypeEnum[keyof typeof ScheduledScanApiModelScheduleRunTypeEnum];
/**
 * @export
 */
export declare const ScheduledScanApiModelCustomScriptTemplateTypeEnum: {
    readonly Default: "Default";
    readonly SimpleLoginForm: "SimpleLoginForm";
    readonly SimpleLoginFormQuery: "SimpleLoginFormQuery";
    readonly SimpleLoginFormDelay: "SimpleLoginFormDelay";
};
export type ScheduledScanApiModelCustomScriptTemplateTypeEnum = typeof ScheduledScanApiModelCustomScriptTemplateTypeEnum[keyof typeof ScheduledScanApiModelCustomScriptTemplateTypeEnum];
/**
 * @export
 */
export declare const ScheduledScanApiModelCreateTypeEnum: {
    readonly Website: "Website";
    readonly WebsiteGroup: "WebsiteGroup";
};
export type ScheduledScanApiModelCreateTypeEnum = typeof ScheduledScanApiModelCreateTypeEnum[keyof typeof ScheduledScanApiModelCreateTypeEnum];
/**
 * Check if a given object implements the ScheduledScanApiModel interface.
 */
export declare function instanceOfScheduledScanApiModel(value: object): boolean;
export declare function ScheduledScanApiModelFromJSON(json: any): ScheduledScanApiModel;
export declare function ScheduledScanApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScheduledScanApiModel;
export declare function ScheduledScanApiModelToJSON(value?: Omit<ScheduledScanApiModel, 'CustomScriptTemplateType' | 'IsTargetUrlRequired' | 'CanEdit'> | null): any;