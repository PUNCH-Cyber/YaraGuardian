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


yaraGuardian.config(function($httpProvider) {
    // Configure ajax requests header for Django application
    $httpProvider.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';

    // Configure Angular for Django CSRF
    $httpProvider.defaults.xsrfCookieName = 'csrftoken';
    $httpProvider.defaults.xsrfHeaderName = 'X-CSRFToken';

    // Initialize get header if not already existent
    if (!$httpProvider.defaults.headers.get) {
        $httpProvider.defaults.headers.get = {};    
    } 

    // Disable IE ajax request caching
    $httpProvider.defaults.headers.get['If-Modified-Since'] = 'Mon, 26 Jul 1997 05:00:00 GMT';

    // Disable other cache methods
    $httpProvider.defaults.headers.get['Cache-Control'] = 'no-cache';
    $httpProvider.defaults.headers.get['Pragma'] = 'no-cache';
});
