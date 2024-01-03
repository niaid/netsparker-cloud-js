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
import type { NewScanNotificationRecipientApiModel } from './NewScanNotificationRecipientApiModel';
import type { NotificationEmailSmsFilterApi } from './NotificationEmailSmsFilterApi';
import type { NotificationIntegrationFilterApi } from './NotificationIntegrationFilterApi';
/**
 * Represents a model for carrying out a new scan notification data
 * @export
 * @interface NewScanNotificationApiModel
 */
export interface NewScanNotificationApiModel {
    /**
     *
     * @type {NewScanNotificationRecipientApiModel}
     * @memberof NewScanNotificationApiModel
     */
    recipients: NewScanNotificationRecipientApiModel;
    /**
     * Gets or sets the website group identifier associated with this scan notification.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    websiteGroupName?: string;
    /**
     * Gets or sets the website identifier associated with this scan notification.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    websiteRootUrl?: string;
    /**
     *
     * @type {NotificationEmailSmsFilterApi}
     * @memberof NewScanNotificationApiModel
     */
    emailSmsFilter?: NotificationEmailSmsFilterApi;
    /**
     *
     * @type {NotificationIntegrationFilterApi}
     * @memberof NewScanNotificationApiModel
     */
    integrationFilter?: NotificationIntegrationFilterApi;
    /**
     * Gets or sets a value indicating whether this Scan Notification is disabled.
     * @type {boolean}
     * @memberof NewScanNotificationApiModel
     */
    disabled: boolean;
    /**
     * Gets or sets scan task group ID.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    scanTaskGroupId?: string;
    /**
     * Gets or sets the event name. This property determines when this rule will be executed.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    event: NewScanNotificationApiModelEventEnum;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    name: string;
    /**
     * Gets or sets the Website Scope.
     * This property indicates whether this rule will be executed for a specific Website, WebsiteGroup or All Websites.
     * @type {string}
     * @memberof NewScanNotificationApiModel
     */
    scope: NewScanNotificationApiModelScopeEnum;
}
/**
* @export
* @enum {string}
*/
export declare enum NewScanNotificationApiModelEventEnum {
    NewScan = "NewScan",
    ScanCompleted = "ScanCompleted",
    ScanCancelled = "ScanCancelled",
    ScanFailed = "ScanFailed",
    ScheduledScanLaunchFailed = "ScheduledScanLaunchFailed",
    OutOfDateTechnology = "OutOfDateTechnology"
}
/**
* @export
* @enum {string}
*/
export declare enum NewScanNotificationApiModelScopeEnum {
    AnyWebsite = "AnyWebsite",
    WebsiteGroup = "WebsiteGroup",
    Website = "Website"
}
/**
 * Check if a given object implements the NewScanNotificationApiModel interface.
 */
export declare function instanceOfNewScanNotificationApiModel(value: object): boolean;
export declare function NewScanNotificationApiModelFromJSON(json: any): NewScanNotificationApiModel;
export declare function NewScanNotificationApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): NewScanNotificationApiModel;
export declare function NewScanNotificationApiModelToJSON(value?: NewScanNotificationApiModel | null): any;
