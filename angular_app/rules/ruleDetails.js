var app = angular.module('yaraGuardian.RuleDetails', [
    'ui.bootstrap',
    'yaraGuardian.API',
    'yaraGuardian.RuleStats',
    'yaraGuardian.RuleSearch',
    'yaraGuardian.Messages',
    'yaraGuardian.Services',
    'yaraGuardian.AccountManagement'
]);


app.factory('ruleManagerService', function($uibModal, accountService, apiService, messageService, coreServices, ruleStatService, ruleSearchService) {

    var managerMethods = {};

    managerMethods.selectedRule = {};
    managerMethods.selectedRuleComment = {};

    managerMethods.displayRule = function(ruleObj) {
        managerMethods.selectedRule = ruleObj;
        apiService.ruleRetrieve(accountService.groupContext.name, ruleObj.id).then(ruleRetrieveSuccess, ruleMethodFailure);
    };

    managerMethods.updateRule = function(ruleObj, updateParams) {
        messageService.clearMessages();
        managerMethods.selectedRule = ruleObj;
        apiService.ruleUpdate(accountService.groupContext.name, ruleObj.id, updateParams).then(ruleUpdateSuccess, ruleMethodFailure);
    };

    managerMethods.deleteRule = function(ruleObj) {
        messageService.clearMessages();
        managerMethods.selectedRule = ruleObj;
        apiService.ruleDelete(accountService.groupContext.name, ruleObj.id).then(ruleDeleteSuccess, ruleMethodFailure);
    };

    managerMethods.removeRuleTag = function(ruleObj, tag) {
        messageService.clearMessages();
        managerMethods.selectedRule = ruleObj;
        apiService.ruleRemoveTag(accountService.groupContext.name, ruleObj.id, tag).then(ruleUpdateSuccess, ruleMethodFailure);
    };

    managerMethods.removeRuleMetadata = function(ruleObj, metakey) {
        messageService.clearMessages();
        managerMethods.selectedRule = ruleObj;
        apiService.ruleRemoveMetadata(accountService.groupContext.name, ruleObj.id, metakey).then(ruleUpdateSuccess, ruleMethodFailure);
    };

    managerMethods.displayRuleComments = function(ruleObj) {
        managerMethods.selectedRule = ruleObj;
        apiService.ruleRetrieve(accountService.groupContext.name, ruleObj.id).then(commentRetrieveSuccess, ruleMethodFailure);
    };

    managerMethods.createRuleComment = function(ruleObj, commentContent) {
        managerMethods.selectedRule = ruleObj;
        apiService.commentCreate(accountService.groupContext.name, ruleObj.id, commentContent).then(commentCreateSuccess, ruleMethodFailure);
    };

    managerMethods.deleteRuleComment = function(ruleObj, commentObj) {
        managerMethods.selectedRule = ruleObj;
        managerMethods.selectedRuleComment = commentObj;
        apiService.commentDelete(accountService.groupContext.name, ruleObj.id, commentObj.id).then(commentDeleteSuccess, ruleMethodFailure);
    };

    function ruleRetrieveSuccess(response) {
        coreServices.refreshObject(managerMethods.selectedRule, response.data);

        if (accountService.userIsOwnerOrAdmin()) {
            showRuleWriteModal();
        } else {
            showRuleReadModal();
        };

    };

    function commentRetrieveSuccess(response) {
        coreServices.refreshObject(managerMethods.selectedRule, response.data);

        if (accountService.userIsOwnerOrAdmin()) {
            showCommentWriteModal();
        } else {
            showCommentReadModal();
        };

    };

    function commentCreateSuccess(response) {
        managerMethods.selectedRule.comments.push(response.data)
    };

    function commentDeleteSuccess(response) {
        var index = managerMethods.selectedRule.comments.indexOf(managerMethods.selectedRuleComment);
        managerMethods.selectedRule.comments.splice(index, 1);
    };

    function ruleUpdateSuccess(response) {
        coreServices.refreshObject(managerMethods.selectedRule, response.data);
        ruleStatService.retrieveStats(accountService.groupContext.name);
    };

    function ruleDeleteSuccess(response) {
        var index = ruleSearchService.search.results.indexOf(managerMethods.selectedRule);
        ruleSearchService.search.results.splice(index, 1);
        ruleStatService.retrieveStats(accountService.groupContext.name);
    };

    function ruleMethodFailure(response) {
        messageService.pushMessage(response, 'danger');
    };

    function showRuleReadModal() {
        var modalInstance = $uibModal.open({
            templateUrl: 'ruleModalRead.html',
            controller: 'RuleModalController',
            controllerAs: 'ModalCtrl',
            size: 'lg'
        });
    };

    function showRuleWriteModal() {
        var modalInstance = $uibModal.open({
            templateUrl: 'ruleModalWrite.html',
            controller: 'RuleModalController',
            controllerAs: 'ModalCtrl',
            size: 'lg'
        });
    };

    function showCommentReadModal() {
        var modalInstance = $uibModal.open({
            templateUrl: 'commentModalRead.html',
            controller: 'CommentModalController',
            controllerAs: 'ModalCtrl',
            size: 'lg'
        });
    };

    function showCommentWriteModal() {
        var modalInstance = $uibModal.open({
            templateUrl: 'commentModalWrite.html',
            controller: 'CommentModalController',
            controllerAs: 'ModalCtrl',
            size: 'lg'
        });
    };

    return managerMethods;

});


app.controller('RuleController', function(ruleManagerService) {
    var self = this;

    self.rule = ruleManagerService.selectedRule;

    self.showRule = function(ruleObj) {
        ruleManagerService.displayRule(ruleObj)
    };

    self.updateRule = function(ruleObj, updateParams) {
        ruleManagerService.updateRule(ruleObj, updateParams)
    };

    self.deleteRule = function(ruleObj) {
        ruleManagerService.deleteRule(ruleObj)
    };

    self.removeTag = function(ruleObj, tag) {
        ruleManagerService.removeRuleTag(ruleObj, tag)
    };

    self.removeMetadata = function(ruleObj, metakey) {
        ruleManagerService.removeRuleMetadata(ruleObj, metakey)
    };

    self.showComments = function(ruleObj) {
        ruleManagerService.displayRuleComments(ruleObj)
    };
});


app.controller('RuleModalController', function($uibModalInstance, ruleManagerService) {
    var self = this;

    self.rule = ruleManagerService.selectedRule;

    self.formData = {};
    self.formData.rule_content = self.rule.formatted_rule;

    self.update = function () {
        ruleManagerService.updateRule(self.rule, self.formData);
        $uibModalInstance.close();
    };

    self.cancel = function () {
        $uibModalInstance.dismiss('cancel');
    };

});


app.controller('CommentModalController', function($uibModalInstance, ruleManagerService) {
    var self = this;

    self.rule = ruleManagerService.selectedRule;

    self.commentContent = '';

    self.createComment = function () {
        ruleManagerService.createRuleComment(self.rule, self.commentContent);
    };

    self.deleteComment = function (commentObj) {
        ruleManagerService.deleteRuleComment(self.rule, commentObj);
    };

    self.cancel = function () {
        $uibModalInstance.dismiss('cancel');
    };

});
