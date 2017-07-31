var app = angular.module('yaraGuardian.RuleSubmit', [
    'yaraGuardian.API',
    'yaraGuardian.RuleStats',
    'yaraGuardian.Messages',
    'yaraGuardian.AccountManagement',
]);


app.controller('RuleSubmitController', function(accountService, apiService, messageService, ruleStatService) {
    var self = this;

    self.submission = {};

    self.fileObjects = [];
    self.setMetadata = {};

    self.metaDisplay = {};
    self.metaDisplay.loading = false;

    self.clearFiles = function() {
      // Method to clear file object data
      self.fileObjects.length = 0
    };

    self.submitForm = function() {
        // Build 'set metadata' form data
        if (self.setMetadata.key != "" && self.setMetadata.value != "") {
            self.formData['set_metadata_' + self.setMetadata.key] = self.setMetadata.value;
        };

        // Generate form payload from form data
        angular.forEach(self.formData, function (value, key) {
            self.formPayload.append(key, value);
        });

        // Generate form payload from file objects
        angular.forEach(self.fileObjects, function (fileObject, fileIndex) {
            self.formPayload.append('rule_content', fileObject);
        });

        self.metaDisplay.loading = true;
        apiService.ruleBulkUpload(accountService.groupContext.name, self.formPayload).then(submitSuccess, submitFailure);
    };

    function submitSuccess(response) {
        self.submission = response.data;
        initializeController();

        var uploadMsg = self.submission.rule_upload_count + ' rules submitted';
        var collisionMsg = self.submission.rule_collision_count + ' rule collisions occurred';

        ruleStatService.retrieveStats(accountService.groupContext.name);
        messageService.pushMessage(uploadMsg, 'success');
        messageService.pushMessage(collisionMsg, 'warning');
        messageService.processErrors(self.submission.errors);
        messageService.processWarnings(self.submission.warnings);
    };

    function submitFailure(response) {
        self.submission.errors = response.data;
        initializeController();
    };

    function initializeController() {
        self.clearFiles();
        self.formData = {};

        self.setMetadata.key = "";
        self.setMetadata.value = "";

        self.metaDisplay.loading = false;
        self.formPayload = new FormData();
        messageService.clearMessages();
    };

    initializeController();
});
