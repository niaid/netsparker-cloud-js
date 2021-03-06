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
exports.ApiScanStatusModel = void 0;
/**
* Represents a model for carrying out scan status data for API.
*/
class ApiScanStatusModel {
    static getAttributeTypeMap() {
        return ApiScanStatusModel.attributeTypeMap;
    }
}
exports.ApiScanStatusModel = ApiScanStatusModel;
ApiScanStatusModel.discriminator = undefined;
ApiScanStatusModel.attributeTypeMap = [
    {
        "name": "completedSteps",
        "baseName": "CompletedSteps",
        "type": "number"
    },
    {
        "name": "estimatedLaunchTime",
        "baseName": "EstimatedLaunchTime",
        "type": "number"
    },
    {
        "name": "estimatedSteps",
        "baseName": "EstimatedSteps",
        "type": "number"
    },
    {
        "name": "state",
        "baseName": "State",
        "type": "ApiScanStatusModel.StateEnum"
    }
];
(function (ApiScanStatusModel) {
    let StateEnum;
    (function (StateEnum) {
        StateEnum[StateEnum["Queued"] = 'Queued'] = "Queued";
        StateEnum[StateEnum["Scanning"] = 'Scanning'] = "Scanning";
        StateEnum[StateEnum["Archiving"] = 'Archiving'] = "Archiving";
        StateEnum[StateEnum["Complete"] = 'Complete'] = "Complete";
        StateEnum[StateEnum["Failed"] = 'Failed'] = "Failed";
        StateEnum[StateEnum["Cancelled"] = 'Cancelled'] = "Cancelled";
        StateEnum[StateEnum["Delayed"] = 'Delayed'] = "Delayed";
        StateEnum[StateEnum["Pausing"] = 'Pausing'] = "Pausing";
        StateEnum[StateEnum["Paused"] = 'Paused'] = "Paused";
        StateEnum[StateEnum["Resuming"] = 'Resuming'] = "Resuming";
    })(StateEnum = ApiScanStatusModel.StateEnum || (ApiScanStatusModel.StateEnum = {}));
})(ApiScanStatusModel = exports.ApiScanStatusModel || (exports.ApiScanStatusModel = {}));
//# sourceMappingURL=apiScanStatusModel.js.map