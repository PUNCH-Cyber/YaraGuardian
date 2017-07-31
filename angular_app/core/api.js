var app = angular.module('yaraGuardian.API', ['djng.urls']);


app.config(['$httpProvider', function($httpProvider) {
    $httpProvider.defaults.xsrfCookieName = 'csrftoken';
    $httpProvider.defaults.xsrfHeaderName = 'X-CSRFToken';
}]);


app.factory('apiService', function($location, $http, $q, djangoUrl) {

    var apiMethods = {};

    var apiCallSuccess = function (deferred) {
      return function (response) {deferred.resolve(response)}
    };

    var apiCallError = function (deferred) {
      return function (response) {deferred.reject(response.data.detail)}
    };

    apiMethods.getURL = function(URL) {
        var deferred = $q.defer();
        var protocol = $location.protocol();

        // Proxy handling
        if (protocol == 'https' && !(URL.startsWith('https'))) {
          URL = URL.replace("http", "https");
        };

        $http.get(URL, {'Cache-Control': 'no-cache'}).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleStats = function(groupContext, params) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('ruleset-stats', {'group_name': groupContext});
        var data = {'params': params, 'Cache-Control': 'no-cache'};
        $http.get(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleList = function(groupContext, params) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('ruleset-search', {'group_name': groupContext});
        var data = {'params': params, 'Cache-Control': 'no-cache'};
        $http.get(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleCreate = function(groupContext, data) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('ruleset', {'group_name': groupContext});
        $http.post(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleRetrieve = function(groupContext, ruleId) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('rule-details', {'group_name': groupContext, 'rule_pk': ruleId});
        var data = {'Cache-Control': 'no-cache'};
        $http.get(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleUpdate = function(groupContext, ruleId, data) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('rule-details', {'group_name': groupContext, 'rule_pk': ruleId});
        $http.patch(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleDelete = function(groupContext, ruleId) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('rule-details', {'group_name': groupContext, 'rule_pk': ruleId});
        $http.delete(url).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleBulkUpdate = function(groupContext, params, data) {
        var deferred = $q.defer();

        var apiCall = {
          method: 'PATCH',
          url: djangoUrl.reverse('ruleset-bulk', {'group_name': groupContext}),
          params: params,
          data: data
        };

        $http(apiCall).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleBulkUpload = function(groupContext, data) {
        var deferred = $q.defer();

        var apiCall = {
          method: 'POST',
          url: djangoUrl.reverse('ruleset-bulk', {'group_name': groupContext}),
          headers: {'Content-Type': undefined},
          data: data
        };

        $http(apiCall).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleBulkDelete = function(groupContext, params) {
        var deferred = $q.defer();

        var apiCall = {
          method: 'DELETE',
          url: djangoUrl.reverse('ruleset-bulk', {'group_name': groupContext}),
          params: params,
        };

        $http(apiCall).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleRemoveTag = function(groupContext, ruleId, tag) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('rule-tags', {'group_name': groupContext, 'rule_pk': ruleId, 'tag': tag});
        $http.delete(url).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.ruleRemoveMetadata = function(groupContext, ruleId, metakey) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('rule-metadata', {'group_name': groupContext, 'rule_pk': ruleId, 'metakey': metakey});
        $http.delete(url).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupList = function() {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('account-groups');
        $http.get(url).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupCreate = function(data) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('account-groups');
        $http.post(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupDetails = function(groupName) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('group-details', {'group_name': groupName});
        $http.get(url).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupUpdate = function(groupName, data) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('group-details', {'group_name': groupName});
        $http.patch(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupDelete = function(groupName) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('group-details', {'group_name': groupName});
        $http.delete(url).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupAddCategory = function(groupName, data) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('group-categories', {'group_name': groupName});
        $http.patch(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupRemoveCategory = function(groupName, params) {
        var deferred = $q.defer();

        var apiCall = {
          method: 'DELETE',
          url: djangoUrl.reverse('group-categories', {'group_name': groupName}),
          params: params,
        };

        $http(apiCall).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupAddSource = function(groupName, data) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('group-sources', {'group_name': groupName});
        $http.patch(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupRemoveSource = function(groupName, params) {
        var deferred = $q.defer();

        var apiCall = {
          method: 'DELETE',
          url: djangoUrl.reverse('group-sources', {'group_name': groupName}),
          params: params,
        };

        $http(apiCall).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupAddMember = function(groupName, data) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('group-members', {'group_name': groupName});
        $http.patch(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupRemoveMember = function(groupName, params) {
        var deferred = $q.defer();

        var apiCall = {
          method: 'DELETE',
          url: djangoUrl.reverse('group-members', {'group_name': groupName}),
          params: params,
        };

        $http(apiCall).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupAddAdmin = function(groupName, data) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('group-admins', {'group_name': groupName});
        $http.patch(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.groupRemoveAdmin = function(groupName, params) {
        var deferred = $q.defer();

        var apiCall = {
          method: 'DELETE',
          url: djangoUrl.reverse('group-admins', {'group_name': groupName}),
          params: params,
        };

        $http(apiCall).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.commentCreate = function(groupContext, ruleId, commentContent) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('rule-comments', {'group_name': groupContext, 'rule_pk': ruleId});
        var data = {'content': commentContent};
        $http.post(url, data).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.commentDelete = function(groupContext, ruleId, commentId) {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('rule-comment-details', {'group_name': groupContext, 'rule_pk': ruleId, 'comment_pk': commentId});
        $http.delete(url).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    apiMethods.accountDetails = function() {
        var deferred = $q.defer();
        var url = djangoUrl.reverse('account');
        $http.get(url).then(apiCallSuccess(deferred), apiCallError(deferred));
        return deferred.promise;
    };

    return apiMethods;
});
