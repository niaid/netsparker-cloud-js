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
import type { NotificationEmailSmsFilterApi } from './NotificationEmailSmsFilterApi';
import type { NotificationIntegrationFilterApi } from './NotificationIntegrationFilterApi';
import type { ScanNotificationRecipientApiModel } from './ScanNotificationRecipientApiModel';
/**
 * Represents a model for carrying out scan notification data
 * @export
 * @interface ScanNotificationApiModel
 */
export interface ScanNotificationApiModel {
    /**
     * Gets or sets the scan notification identifier.
     * @type {string}
     * @memberof ScanNotificationApiModel
     */
    id?: string;
    /**
     * Gets or sets the priority. Higher value means higher priority.
     * @type {number}
     * @memberof ScanNotificationApiModel
     */
    priority?: number;
    /**
     *
     * @type {ScanNotificationRecipientApiModel}
     * @memberof ScanNotificationApiModel
     */
    recipients?: ScanNotificationRecipientApiModel;
    /**
     * Gets or sets the name of website group associated with this Scan Notification.
     * @type {string}
     * @memberof ScanNotificationApiModel
     */
    websiteGroupName?: string;
    /**
     * Gets or sets the root url of website associated with this Scan Notification.
     * @type {string}
     * @memberof ScanNotificationApiModel
     */
    websiteRootUrl?: string;
    /**
     *
     * @type {NotificationEmailSmsFilterApi}
     * @memberof ScanNotificationApiModel
     */
    emailSmsFilter?: NotificationEmailSmsFilterApi;
    /**
     *
     * @type {NotificationIntegrationFilterApi}
     * @memberof ScanNotificationApiModel
     */
    integrationFilter?: NotificationIntegrationFilterApi;
    /**
     * Gets or sets a value indicating whether this Scan Notification is disabled.
     * @type {boolean}
     * @memberof ScanNotificationApiModel
     */
    disabled: boolean;
    /**
     * Gets or sets scan task group ID.
     * @type {string}
     * @memberof ScanNotificationApiModel
     */
    scanTaskGroupId?: string;
    /**
     * Gets or sets the event name. This property determines when this rule will be executed.
     * @type {string}
     * @memberof ScanNotificationApiModel
     */
    event: ScanNotificationApiModelEventEnum;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof ScanNotificationApiModel
     */
    name: string;
    /**
     * Gets or sets the Website Scope.
     * This property indicates whether this rule will be executed for a specific Website, WebsiteGroup or All Websites.
     * @type {string}
     * @memberof ScanNotificationApiModel
     */
    scope: ScanNotificationApiModelScopeEnum;
}
/**
 * @export
 */
export declare const ScanNotificationApiModelEventEnum: {
    readonly NewScan: "NewScan";
    readonly ScanCompleted: "ScanCompleted";
    readonly ScanCancelled: "ScanCancelled";
    readonly ScanFailed: "ScanFailed";
    readonly ScheduledScanLaunchFailed: "ScheduledScanLaunchFailed";
    readonly OutOfDateTechnology: "OutOfDateTechnology";
};
export type ScanNotificationApiModelEventEnum = typeof ScanNotificationApiModelEventEnum[keyof typeof ScanNotificationApiModelEventEnum];
/**
 * @export
 */
export declare const ScanNotificationApiModelScopeEnum: {
    readonly AnyWebsite: "AnyWebsite";
    readonly WebsiteGroup: "WebsiteGroup";
    readonly Website: "Website";
};
export type ScanNotificationApiModelScopeEnum = typeof ScanNotificationApiModelScopeEnum[keyof typeof ScanNotificationApiModelScopeEnum];
/**
 * Check if a given object implements the ScanNotificationApiModel interface.
 */
export declare function instanceOfScanNotificationApiModel(value: object): boolean;
export declare function ScanNotificationApiModelFromJSON(json: any): ScanNotificationApiModel;
export declare function ScanNotificationApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanNotificationApiModel;
export declare function ScanNotificationApiModelToJSON(value?: ScanNotificationApiModel | null): any;
