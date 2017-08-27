var app = angular.module('yaraGuardian.AccountManagement', [
    'yaraGuardian.API',
    'yaraGuardian.RuleStats',
    'yaraGuardian.RuleSearch',
    'yaraGuardian.Services',
    'ui.bootstrap'
]);


app.factory('accountService', function($uibModal, apiService, coreServices, ruleSearchService, ruleStatService) {

    var accountMethods = {};
    accountMethods.account = {};
    accountMethods.groupContext = {};

    accountMethods.retrieveAccount = function() {
        apiService.accountDetails().then(accountRetrieveSuccess, accountRetrieveFailure);
    };

    accountMethods.retrieveGroup = function(groupName) {
        apiService.groupDetails(groupName).then(groupRetrieveSuccess, groupRetrieveFailure);
    };

    accountMethods.refreshGroup = function() {
        apiService.groupDetails(accountMethods.groupContext.name).then(groupRetrieveSuccess, groupRetrieveFailure);
    };

    accountMethods.displayAccountDetails = function() {
        showAccountReadModal();
    };

    accountMethods.userIsOwnerOrAdmin = function() {
        if ((Object.keys(accountMethods.groupContext).length !== 0) && (Object.keys(accountMethods.account).length !== 0)) {
            if (accountMethods.account.username === accountMethods.groupContext.owner) {return true};
            if (accountMethods.groupContext.members[accountMethods.account.username].membership === "admin") {return true};
        }
        return false;
    };

    accountMethods.userIsOwner = function() {
        if ((Object.keys(accountMethods.groupContext).length !== 0) && (Object.keys(accountMethods.account).length !== 0)) {
            if (accountMethods.account.username === accountMethods.groupContext.owner) {return true};
        }
        return false;
    };

    function accountRetrieveSuccess(response) {
        coreServices.refreshObject(accountMethods.account, response.data);

        if (Object.keys(accountMethods.groupContext).length === 0) {
            accountMethods.retrieveGroup(accountMethods.account.username);
        }
    }

    function accountRetrieveFailure(response) {console.log(response)};

    function groupRetrieveSuccess(response) {
        coreServices.refreshObject(accountMethods.groupContext, response.data);
        ruleSearchService.refreshSearch(accountMethods.groupContext.name);
        ruleStatService.retrieveStats(accountMethods.groupContext.name);
    }

    function groupRetrieveFailure(response) {console.log(response)};

    function showAccountReadModal() {
        var modalInstance = $uibModal.open({
            templateUrl: 'accountModalRead.html',
            controller: 'AccountModalController',
            controllerAs: 'ModalCtrl',
            size: 'md'
        });
    }

    return accountMethods;
});


app.controller('AccountManagementController', function(accountService) {

    var self = this;

    self.account = accountService.account;
    self.group = accountService.groupContext;

    self.switchGroup = function(groupName) {
        accountService.retrieveGroup(groupName);
    };

    self.showAccountDetails = function() {
        accountService.displayAccountDetails();
    };

    self.userIsOwner = function() {
        return accountService.userIsOwner();
    };

    self.userIsOwnerOrAdmin = function() {
        return accountService.userIsOwnerOrAdmin();
    };

    accountService.retrieveAccount();
});


app.controller('AccountModalController', function($uibModalInstance, accountService) {
    var self = this;

    self.account = accountService.account;

    self.cancel = function () {
        $uibModalInstance.dismiss('cancel');
    };

});
