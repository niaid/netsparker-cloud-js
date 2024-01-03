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
exports.NewScheduledIncrementalScanApiModelToJSON = exports.NewScheduledIncrementalScanApiModelFromJSONTyped = exports.NewScheduledIncrementalScanApiModelFromJSON = exports.instanceOfNewScheduledIncrementalScanApiModel = exports.NewScheduledIncrementalScanApiModelScheduleRunTypeEnum = void 0;
const runtime_1 = require("../runtime");
/**
* @export
* @enum {string}
*/
var NewScheduledIncrementalScanApiModelScheduleRunTypeEnum;
(function (NewScheduledIncrementalScanApiModelScheduleRunTypeEnum) {
    NewScheduledIncrementalScanApiModelScheduleRunTypeEnum["Once"] = "Once";
    NewScheduledIncrementalScanApiModelScheduleRunTypeEnum["Daily"] = "Daily";
    NewScheduledIncrementalScanApiModelScheduleRunTypeEnum["Weekly"] = "Weekly";
    NewScheduledIncrementalScanApiModelScheduleRunTypeEnum["Monthly"] = "Monthly";
    NewScheduledIncrementalScanApiModelScheduleRunTypeEnum["Quarterly"] = "Quarterly";
    NewScheduledIncrementalScanApiModelScheduleRunTypeEnum["Biannually"] = "Biannually";
    NewScheduledIncrementalScanApiModelScheduleRunTypeEnum["Yearly"] = "Yearly";
    NewScheduledIncrementalScanApiModelScheduleRunTypeEnum["Custom"] = "Custom";
})(NewScheduledIncrementalScanApiModelScheduleRunTypeEnum = exports.NewScheduledIncrementalScanApiModelScheduleRunTypeEnum || (exports.NewScheduledIncrementalScanApiModelScheduleRunTypeEnum = {}));
/**
 * Check if a given object implements the NewScheduledIncrementalScanApiModel interface.
 */
function instanceOfNewScheduledIncrementalScanApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "nextExecutionTime" in value;
    isInstance = isInstance && "scheduleRunType" in value;
    isInstance = isInstance && "baseScanId" in value;
    return isInstance;
}
exports.instanceOfNewScheduledIncrementalScanApiModel = instanceOfNewScheduledIncrementalScanApiModel;
function NewScheduledIncrementalScanApiModelFromJSON(json) {
    return NewScheduledIncrementalScanApiModelFromJSONTyped(json, false);
}
exports.NewScheduledIncrementalScanApiModelFromJSON = NewScheduledIncrementalScanApiModelFromJSON;
function NewScheduledIncrementalScanApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'isMaxScanDurationEnabled': !(0, runtime_1.exists)(json, 'IsMaxScanDurationEnabled') ? undefined : json['IsMaxScanDurationEnabled'],
        'maxScanDuration': !(0, runtime_1.exists)(json, 'MaxScanDuration') ? undefined : json['MaxScanDuration'],
        'name': json['Name'],
        'nextExecutionTime': json['NextExecutionTime'],
        'scheduleRunType': json['ScheduleRunType'],
        'tags': !(0, runtime_1.exists)(json, 'Tags') ? undefined : json['Tags'],
        'agentName': !(0, runtime_1.exists)(json, 'AgentName') ? undefined : json['AgentName'],
        'baseScanId': json['BaseScanId'],
    };
}
exports.NewScheduledIncrementalScanApiModelFromJSONTyped = NewScheduledIncrementalScanApiModelFromJSONTyped;
function NewScheduledIncrementalScanApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'IsMaxScanDurationEnabled': value.isMaxScanDurationEnabled,
        'MaxScanDuration': value.maxScanDuration,
        'Name': value.name,
        'NextExecutionTime': value.nextExecutionTime,
        'ScheduleRunType': value.scheduleRunType,
        'Tags': value.tags,
        'AgentName': value.agentName,
        'BaseScanId': value.baseScanId,
    };
}
exports.NewScheduledIncrementalScanApiModelToJSON = NewScheduledIncrementalScanApiModelToJSON;
//# sourceMappingURL=NewScheduledIncrementalScanApiModel.js.map