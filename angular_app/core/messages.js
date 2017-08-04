var app = angular.module('yaraGuardian.Messages', []);

app.factory('messageService', function() {

    var messageMethods = {};
    messageMethods.messages = [];

    messageMethods.pushMessage = function (_msgContent, _msgType) {
    	var _message = {'message': _msgContent, 'type': _msgType};
    	messageMethods.messages.push(_message);
    };

    messageMethods.deleteMessage = function(_index) {
        messageMethods.messages.splice(_index, 1);
    };

    messageMethods.clearMessages = function () {
        messageMethods.messages.length = 0;
    };

    messageMethods.processErrors = function (errorArray) {
        angular.forEach(errorArray, function (msgContent) {
            messageMethods.pushMessage(msgContent, 'danger');
        });
    };

    messageMethods.processWarnings = function(warningArray) {
        angular.forEach(warningArray, function (msgContent) {
            messageMethods.pushMessage(msgContent, 'warning');
        });
    };

    messageMethods.processChanges = function(changesArray) {
        angular.forEach(changesArray, function (msgContent) {
            messageMethods.pushMessage(msgContent, 'success');
        });
    };
    
    return messageMethods;
});


app.controller('MessageController', function($scope, messageService) {
    $scope.messages = messageService.messages;

    $scope.closeAlert = function(index) {
        $scope.messages.splice(index, 1);
    };
});
