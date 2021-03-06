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
exports.ScheduledScanRecurrenceViewModel = void 0;
/**
* Scheduled scan recurrence view model.
*/
class ScheduledScanRecurrenceViewModel {
    static getAttributeTypeMap() {
        return ScheduledScanRecurrenceViewModel.attributeTypeMap;
    }
}
exports.ScheduledScanRecurrenceViewModel = ScheduledScanRecurrenceViewModel;
ScheduledScanRecurrenceViewModel.discriminator = undefined;
ScheduledScanRecurrenceViewModel.attributeTypeMap = [
    {
        "name": "repeatType",
        "baseName": "RepeatType",
        "type": "ScheduledScanRecurrenceViewModel.RepeatTypeEnum"
    },
    {
        "name": "interval",
        "baseName": "Interval",
        "type": "number"
    },
    {
        "name": "startDate",
        "baseName": "StartDate",
        "type": "Date"
    },
    {
        "name": "endingType",
        "baseName": "EndingType",
        "type": "ScheduledScanRecurrenceViewModel.EndingTypeEnum"
    },
    {
        "name": "daysOfWeek",
        "baseName": "DaysOfWeek",
        "type": "Array<ScheduledScanRecurrenceViewModel.DaysOfWeekEnum>"
    },
    {
        "name": "monthsOfYear",
        "baseName": "MonthsOfYear",
        "type": "Array<ScheduledScanRecurrenceViewModel.MonthsOfYearEnum>"
    },
    {
        "name": "ordinal",
        "baseName": "Ordinal",
        "type": "ScheduledScanRecurrenceViewModel.OrdinalEnum"
    },
    {
        "name": "endOn",
        "baseName": "EndOn",
        "type": "string"
    },
    {
        "name": "endOnOccurences",
        "baseName": "EndOnOccurences",
        "type": "number"
    },
    {
        "name": "dayOfMonth",
        "baseName": "DayOfMonth",
        "type": "number"
    },
    {
        "name": "endOnDate",
        "baseName": "EndOnDate",
        "type": "Date"
    },
    {
        "name": "dayOfWeek",
        "baseName": "DayOfWeek",
        "type": "ScheduledScanRecurrenceViewModel.DayOfWeekEnum"
    }
];
(function (ScheduledScanRecurrenceViewModel) {
    let RepeatTypeEnum;
    (function (RepeatTypeEnum) {
        RepeatTypeEnum[RepeatTypeEnum["Days"] = 'Days'] = "Days";
        RepeatTypeEnum[RepeatTypeEnum["Weeks"] = 'Weeks'] = "Weeks";
        RepeatTypeEnum[RepeatTypeEnum["Months"] = 'Months'] = "Months";
        RepeatTypeEnum[RepeatTypeEnum["Years"] = 'Years'] = "Years";
    })(RepeatTypeEnum = ScheduledScanRecurrenceViewModel.RepeatTypeEnum || (ScheduledScanRecurrenceViewModel.RepeatTypeEnum = {}));
    let EndingTypeEnum;
    (function (EndingTypeEnum) {
        EndingTypeEnum[EndingTypeEnum["Never"] = 'Never'] = "Never";
        EndingTypeEnum[EndingTypeEnum["Date"] = 'Date'] = "Date";
        EndingTypeEnum[EndingTypeEnum["Occurences"] = 'Occurences'] = "Occurences";
    })(EndingTypeEnum = ScheduledScanRecurrenceViewModel.EndingTypeEnum || (ScheduledScanRecurrenceViewModel.EndingTypeEnum = {}));
    let DaysOfWeekEnum;
    (function (DaysOfWeekEnum) {
        DaysOfWeekEnum[DaysOfWeekEnum["Sunday"] = 'Sunday'] = "Sunday";
        DaysOfWeekEnum[DaysOfWeekEnum["Monday"] = 'Monday'] = "Monday";
        DaysOfWeekEnum[DaysOfWeekEnum["Tuesday"] = 'Tuesday'] = "Tuesday";
        DaysOfWeekEnum[DaysOfWeekEnum["Wednesday"] = 'Wednesday'] = "Wednesday";
        DaysOfWeekEnum[DaysOfWeekEnum["Thursday"] = 'Thursday'] = "Thursday";
        DaysOfWeekEnum[DaysOfWeekEnum["Friday"] = 'Friday'] = "Friday";
        DaysOfWeekEnum[DaysOfWeekEnum["Saturday"] = 'Saturday'] = "Saturday";
    })(DaysOfWeekEnum = ScheduledScanRecurrenceViewModel.DaysOfWeekEnum || (ScheduledScanRecurrenceViewModel.DaysOfWeekEnum = {}));
    let MonthsOfYearEnum;
    (function (MonthsOfYearEnum) {
        MonthsOfYearEnum[MonthsOfYearEnum["January"] = 'January'] = "January";
        MonthsOfYearEnum[MonthsOfYearEnum["February"] = 'February'] = "February";
        MonthsOfYearEnum[MonthsOfYearEnum["March"] = 'March'] = "March";
        MonthsOfYearEnum[MonthsOfYearEnum["April"] = 'April'] = "April";
        MonthsOfYearEnum[MonthsOfYearEnum["May"] = 'May'] = "May";
        MonthsOfYearEnum[MonthsOfYearEnum["June"] = 'June'] = "June";
        MonthsOfYearEnum[MonthsOfYearEnum["July"] = 'July'] = "July";
        MonthsOfYearEnum[MonthsOfYearEnum["August"] = 'August'] = "August";
        MonthsOfYearEnum[MonthsOfYearEnum["September"] = 'September'] = "September";
        MonthsOfYearEnum[MonthsOfYearEnum["October"] = 'October'] = "October";
        MonthsOfYearEnum[MonthsOfYearEnum["November"] = 'November'] = "November";
        MonthsOfYearEnum[MonthsOfYearEnum["December"] = 'December'] = "December";
    })(MonthsOfYearEnum = ScheduledScanRecurrenceViewModel.MonthsOfYearEnum || (ScheduledScanRecurrenceViewModel.MonthsOfYearEnum = {}));
    let OrdinalEnum;
    (function (OrdinalEnum) {
        OrdinalEnum[OrdinalEnum["First"] = 'First'] = "First";
        OrdinalEnum[OrdinalEnum["Second"] = 'Second'] = "Second";
        OrdinalEnum[OrdinalEnum["Third"] = 'Third'] = "Third";
        OrdinalEnum[OrdinalEnum["Fourth"] = 'Fourth'] = "Fourth";
        OrdinalEnum[OrdinalEnum["Last"] = 'Last'] = "Last";
    })(OrdinalEnum = ScheduledScanRecurrenceViewModel.OrdinalEnum || (ScheduledScanRecurrenceViewModel.OrdinalEnum = {}));
    let DayOfWeekEnum;
    (function (DayOfWeekEnum) {
        DayOfWeekEnum[DayOfWeekEnum["Sunday"] = 'Sunday'] = "Sunday";
        DayOfWeekEnum[DayOfWeekEnum["Monday"] = 'Monday'] = "Monday";
        DayOfWeekEnum[DayOfWeekEnum["Tuesday"] = 'Tuesday'] = "Tuesday";
        DayOfWeekEnum[DayOfWeekEnum["Wednesday"] = 'Wednesday'] = "Wednesday";
        DayOfWeekEnum[DayOfWeekEnum["Thursday"] = 'Thursday'] = "Thursday";
        DayOfWeekEnum[DayOfWeekEnum["Friday"] = 'Friday'] = "Friday";
        DayOfWeekEnum[DayOfWeekEnum["Saturday"] = 'Saturday'] = "Saturday";
    })(DayOfWeekEnum = ScheduledScanRecurrenceViewModel.DayOfWeekEnum || (ScheduledScanRecurrenceViewModel.DayOfWeekEnum = {}));
})(ScheduledScanRecurrenceViewModel = exports.ScheduledScanRecurrenceViewModel || (exports.ScheduledScanRecurrenceViewModel = {}));
//# sourceMappingURL=scheduledScanRecurrenceViewModel.js.map