'use strict';

var yaraGuardian = angular.module('yaraGuardian', [
    'ngRoute',
    'ngFileUpload',
    'ui.bootstrap',
    'am.multiselect',
    'yaraGuardian.API',
    'yaraGuardian.Filters',
    'yaraGuardian.Directives',
    'yaraGuardian.Services',
    'yaraGuardian.RuleStats',
    'yaraGuardian.RuleSubmit',
    'yaraGuardian.RuleSearch',
    'yaraGuardian.RuleBulkEdit',
    'yaraGuardian.RuleDetails',
    'yaraGuardian.AccountManagement',
    'yaraGuardian.GroupManagement'
]);
