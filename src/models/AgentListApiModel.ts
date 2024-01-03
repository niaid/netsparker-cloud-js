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

import { exists, mapValues } from '../runtime';
/**
 * Initializes a new instance of the {Netsparker.Cloud.Infrastructure.Models.AgentListApiModel} class.
 * @export
 * @interface AgentListApiModel
 */
export interface AgentListApiModel {
    /**
     * Gets or sets the unique identifier of agent.
     * @type {string}
     * @memberof AgentListApiModel
     */
    id?: string;
    /**
     * Gets or sets the date and time at which the instance last notified its active status.
     * @type {Date}
     * @memberof AgentListApiModel
     */
    heartbeat?: Date;
    /**
     * Gets or sets the public ip address of the instance in which this agent runs.
     * @type {string}
     * @memberof AgentListApiModel
     */
    ipAddress?: string;
    /**
     * Gets or sets the date and time at which the instance was launched.
     * @type {Date}
     * @memberof AgentListApiModel
     */
    launched?: Date;
    /**
     * Gets or sets the agent name.
     * @type {string}
     * @memberof AgentListApiModel
     */
    name?: string;
    /**
     * Gets or sets a value that represents the status of this agent instance.
     * @type {string}
     * @memberof AgentListApiModel
     */
    state?: AgentListApiModelStateEnum;
    /**
     * Gets or sets the version of agent.
     * @type {string}
     * @memberof AgentListApiModel
     */
    version?: string;
    /**
     * Determines whether is auto update enabled for the agent.
     * @type {boolean}
     * @memberof AgentListApiModel
     */
    autoUpdateEnabled?: boolean;
    /**
     * Returns an agent has any uncompleted command.
     * @type {boolean}
     * @memberof AgentListApiModel
     */
    hasWaitingCommand?: boolean;
    /**
     * Gets or sets the vdb version
     * @type {string}
     * @memberof AgentListApiModel
     */
    vdbVersion?: string;
    /**
     * Gets or sets the OS Description
     * @type {string}
     * @memberof AgentListApiModel
     */
    osDescription?: string;
    /**
     * Gets or sets the framework description.
     * @type {string}
     * @memberof AgentListApiModel
     */
    frameworkDescription?: string;
    /**
     * Gets or sets the OS architecture
     * @type {string}
     * @memberof AgentListApiModel
     */
    osArchitecture?: string;
    /**
     * Gets or sets the process architecture
     * @type {string}
     * @memberof AgentListApiModel
     */
    processArchitecture?: string;
    /**
     * Gets the agent needs update
     * @type {boolean}
     * @memberof AgentListApiModel
     */
    isAgentNeedsUpdate?: boolean;
}

/**
* @export
* @enum {string}
*/
export enum AgentListApiModelStateEnum {
    Launching = 'Launching',
    Waiting = 'Waiting',
    Scanning = 'Scanning',
    Terminated = 'Terminated',
    NotAvailable = 'NotAvailable',
    Disabled = 'Disabled',
    Updating = 'Updating'
}


/**
 * Check if a given object implements the AgentListApiModel interface.
 */
export function instanceOfAgentListApiModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function AgentListApiModelFromJSON(json: any): AgentListApiModel {
    return AgentListApiModelFromJSONTyped(json, false);
}

export function AgentListApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentListApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'heartbeat': !exists(json, 'Heartbeat') ? undefined : (new Date(json['Heartbeat'])),
        'ipAddress': !exists(json, 'IpAddress') ? undefined : json['IpAddress'],
        'launched': !exists(json, 'Launched') ? undefined : (new Date(json['Launched'])),
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'state': !exists(json, 'State') ? undefined : json['State'],
        'version': !exists(json, 'Version') ? undefined : json['Version'],
        'autoUpdateEnabled': !exists(json, 'AutoUpdateEnabled') ? undefined : json['AutoUpdateEnabled'],
        'hasWaitingCommand': !exists(json, 'HasWaitingCommand') ? undefined : json['HasWaitingCommand'],
        'vdbVersion': !exists(json, 'VdbVersion') ? undefined : json['VdbVersion'],
        'osDescription': !exists(json, 'OsDescription') ? undefined : json['OsDescription'],
        'frameworkDescription': !exists(json, 'FrameworkDescription') ? undefined : json['FrameworkDescription'],
        'osArchitecture': !exists(json, 'OsArchitecture') ? undefined : json['OsArchitecture'],
        'processArchitecture': !exists(json, 'ProcessArchitecture') ? undefined : json['ProcessArchitecture'],
        'isAgentNeedsUpdate': !exists(json, 'IsAgentNeedsUpdate') ? undefined : json['IsAgentNeedsUpdate'],
    };
}

export function AgentListApiModelToJSON(value?: AgentListApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Id': value.id,
        'Heartbeat': value.heartbeat === undefined ? undefined : (value.heartbeat.toISOString()),
        'IpAddress': value.ipAddress,
        'Launched': value.launched === undefined ? undefined : (value.launched.toISOString()),
        'Name': value.name,
        'State': value.state,
        'Version': value.version,
        'AutoUpdateEnabled': value.autoUpdateEnabled,
        'HasWaitingCommand': value.hasWaitingCommand,
        'VdbVersion': value.vdbVersion,
        'OsDescription': value.osDescription,
        'FrameworkDescription': value.frameworkDescription,
        'OsArchitecture': value.osArchitecture,
        'ProcessArchitecture': value.processArchitecture,
        'IsAgentNeedsUpdate': value.isAgentNeedsUpdate,
    };
}

