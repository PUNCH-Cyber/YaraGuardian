var app = angular.module('yaraGuardian.RuleBulkEdit', [
    'yaraGuardian.API',
    'yaraGuardian.Services',
    'yaraGuardian.RuleStats',
    'yaraGuardian.RuleSearch',
    'yaraGuardian.Messages',
    'yaraGuardian.AccountManagement'
]);


app.controller('RuleBulkController', function($httpParamSerializer, apiService, coreServices, accountService, messageService, ruleSearchService, ruleStatService) {
    var self = this;

    self.formData = {};
    self.paramData = {};

    self.editSubmission = {};

    self.nameEditOptions = [{'label': 'lowercase', 'display': 'Lowercase Name or Substring', 'command': 'lowercase_name'},
                            {'label': 'uppercase', 'display': 'Uppecase Name or Substring', 'command': 'uppercase_name'},
                            {'label': 'append', 'display': 'Append Value to Name', 'command': 'append_name'},
                            {'label': 'prepend', 'display': 'Prepend Value to Name', 'command': 'prepend_name'},
                            {'label': 'remove', 'display': 'Remove Substring Value from Name', 'command': 'remove_name'}];

    self.metakeyEditOptions = [{'label': 'lowercase', 'display': 'Lowercase Metadata Key or Substring', 'command': 'lowercase_metakey_'},
                               {'label': 'uppercase', 'display': 'Uppercase Metadata Key or Substring', 'command': 'uppercase_metakey_'},
                               {'label': 'rename', 'display': 'Rename Metadata Key', 'command': 'rename_metakey_'}];

    self.nameEditSelection = {};
    self.nameEditSelection.value = "";

    self.metakeyEditSelection = {};
    self.metakeyEditSelection.option = self.metakeyEditOptions[0];
    self.metakeyEditSelection.value = "";

    self.setMetadata = {};
    self.setMetadata.key = "";
    self.setMetadata.value = "";

    self.selectedRules = {};

    self.setParams = function(newParams) {
        self.paramData = newParams;
    };

    self.generateSelectionParam = function() {
        var verifiedSelections = [];

        for (var ruleKey in self.selectedRules){
            if (self.selectedRules[ruleKey] === true){
                verifiedSelections.push(ruleKey);
            }
        }

        return {'identifier': verifiedSelections.join(',')};
    };

    self.editRules = function() {
        buildEdits();
        messageService.clearMessages();
        apiService.ruleBulkUpdate(accountService.groupContext.name, self.paramData, self.formData).then(ruleUpdateSuccess, ruleMethodFailure);
    };

    self.exportRules = function(paramData) {
        // Generate query string
        var qs = $httpParamSerializer(paramData);
        self.download_url = '/API/rules/' + accountService.groupContext.name + '/export?' + qs;
    };

    self.mergeRules = function(paramData) {
        messageService.clearMessages();
        apiService.ruleDeconflictLogic(accountService.groupContext.name, paramData).then(ruleMethodSuccess, ruleMethodFailure);
    };

    self.deleteRules = function(paramData) {
        messageService.clearMessages();
        apiService.ruleBulkDelete(accountService.groupContext.name, paramData).then(ruleDeleteSuccess, ruleMethodFailure);
    };

    function buildEdits() {
        // Build edit command for name update
        if (self.nameEditSelection.option !== undefined) {
            self.formData[self.nameEditSelection.option.command] = self.nameEditSelection.value;
        }

        // Build edit command for metakey edit
        if (self.metakeyEditSelection.key !== undefined) {
            var metakeyCommand = self.metakeyEditSelection.option.command + self.metakeyEditSelection.key;
            self.formData[metakeyCommand] = self.metakeyEditSelection.value;
        }

        // Build edit command for setting metadata
        if (self.setMetadata.key !== "" && self.setMetadata.value !== "") {
            self.formData['set_metadata_' + self.setMetadata.key] = self.setMetadata.value;
        }
    }

    function ruleUpdateSuccess(response) {
        var updateMsg = "Update operation performed on " + response.data['modified_rule_count'] + " rules"
        messageService.pushMessage(updateMsg, 'success');
        messageService.processMessages(response.data);

        ruleSearchService.refreshSearch(accountService.groupContext.name);
        ruleStatService.retrieveStats(accountService.groupContext.name);
        clearForm();
    }

    function ruleDeleteSuccess(response) {
        var updateMsg = "Delete operation performed on " + response.data['deleted_rule_count'] + " rules"
        messageService.pushMessage(updateMsg, 'warning');
        ruleSearchService.refreshSearch(accountService.groupContext.name);
        ruleStatService.retrieveStats(accountService.groupContext.name);
    }

    function ruleMethodSuccess(response) {
      messageService.processMessages(response.data);
      ruleStatService.retrieveStats(accountService.groupContext.name);
    }

    function ruleMethodFailure(response) {
        self.editSubmission.errors = response.data;
    }

    function clearForm() {
        coreServices.clearObject(self.formData);
        coreServices.clearObject(self.setMetadata);
        coreServices.clearObject(self.selectedRules);
        coreServices.clearObject(self.nameEditSelection);
        coreServices.clearObject(self.metakeyEditSelection);

        self.metakeyEditSelection.option = self.metakeyEditOptions[0];
        self.metakeyEditSelection.value = "";

        self.nameEditSelection.value = "";

        self.setMetadata.key = "";
        self.setMetadata.value = "";
    }

});
