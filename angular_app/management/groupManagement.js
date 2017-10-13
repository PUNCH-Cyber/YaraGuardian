var app = angular.module('yaraGuardian.GroupManagement', [
    'yaraGuardian.API',
    'yaraGuardian.Messages',
    'yaraGuardian.Services',
    'yaraGuardian.AccountManagement'
]);


app.factory('groupService', function(apiService, coreServices, accountService, messageService) {

    var groupMethods = {};

    groupMethods.createGroup = function(groupName) {
        var data = {'name': groupName};
        apiService.groupCreate(data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.addMember = function(memberName) {
        var data = {'member': memberName};
        apiService.groupAddMember(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.addSource = function(sourceName) {
        var data = {'source': sourceName};
        apiService.groupAddSource(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.removeSource = function(sourceName) {
        var data = {'source': sourceName};
        apiService.groupRemoveSource(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.setSourceRequirement = function(sourceRequired) {
        var data = {'source_required': sourceRequired};
        apiService.groupUpdate(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.addCategory = function(categoryName) {
        var data = {'category': categoryName};
        apiService.groupAddCategory(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.removeCategory = function(categoryName) {
        var data = {'category': categoryName};
        apiService.groupRemoveCategory(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.setCategoryRequirement = function(categoryRequired) {
        var data = {'category_required': categoryRequired};
        apiService.groupUpdate(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.removeMember = function(memberName) {
        var params = {'member': memberName};
        apiService.groupRemoveMember(accountService.groupContext.name, params).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.addAdmin = function(adminName) {
        var data = {'admin': adminName}
        apiService.groupAddAdmin(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.removeAdmin = function(adminName) {
        var params = {'admin': adminName};
        apiService.groupRemoveAdmin(accountService.groupContext.name, params).then(groupChangeSuccess, groupChangeFailure);
    };

    groupMethods.deleteGroup = function(groupName) {
        apiService.groupDelete(groupName).then(groupDeleteSuccess, groupChangeFailure);
    };

    groupMethods.setSubmissionStatus = function(submissionStatus) {
        var data = {'nonprivileged_submission_status': submissionStatus};
        apiService.groupUpdate(accountService.groupContext.name, data).then(groupChangeSuccess, groupChangeFailure);
    };

    function groupChangeSuccess(response) {
        accountService.retrieveAccount();
        accountService.refreshGroup();
        messageService.pushMessage('Group Updated', 'success');
    }

    function groupDeleteSuccess(response) {
        accountService.retrieveAccount();

        if (!(accountService.groupContext.name in accountService.account.available_groups)) {
            accountService.retrieveGroup(accountService.account.username);
        }

        messageService.pushMessage('Group Deleted', 'warning');
    }

    function groupChangeFailure(response) {
        messageService.processMessages(response.data);
    }

    return groupMethods;
});


app.controller('GroupManagementController', function(groupService) {

    var self = this;

    self.formData = {};

    self.toggleSource = function(value) {
        groupService.setSourceRequirement(value);
    };

    self.toggleCategory = function(value) {
        groupService.setCategoryRequirement(value);
    };
    
    self.setSubmissionStatus = function(value) {
        groupService.setSubmissionStatus(value);
    };

    self.createNewGroup = function() {
        groupService.createGroup(self.formData.groupSubmission);
        coreServices.clearObject(self.formData);
    };

    self.addMemberToGroup = function() {
        groupService.addMember(self.formData.memberSubmission);
        coreServices.clearObject(self.formData);
    };

    self.addCategoryToGroup = function() {
      groupService.addCategory(self.formData.categorySubmission);
      coreServices.clearObject(self.formData);
    };

    self.removeCategoryFromGroup = function(category_name) {
        groupService.removeCategory(category_name);
    };

    self.addSourceToGroup = function() {
      groupService.addSource(self.formData.sourceSubmission);
      coreServices.clearObject(self.formData);
    };

    self.removeSourceFromGroup = function(source_name) {
        groupService.removeSource(source_name);
    };

    self.deleteGroup = function(group_name) {
        groupService.deleteGroup(group_name);
    };

    self.removeMemberFromGroup = function(member_name) {
        groupService.removeMember(member_name);
    };

    self.promoteMemberToAdmin = function(member_name) {
        groupService.addAdmin(member_name);
    };

    self.demoteMemberFromAdmin = function(member_name) {
        groupService.removeAdmin(member_name);
    };

});
