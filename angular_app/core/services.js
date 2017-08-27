var app = angular.module('yaraGuardian.Services', []);


app.factory('coreServices', function() {

    var serviceMethods = {};

    serviceMethods.clearObject = function(clearingObj) {
        for (var objKey in clearingObj){
            if (clearingObj.hasOwnProperty(objKey)){
                delete clearingObj[objKey];
            }
        }
    };

    serviceMethods.refreshObject = function(oldContent, newContent) {
        angular.forEach(newContent, function (contentValue, contentKey) {
            oldContent[contentKey] = contentValue;
        });
    };

    return serviceMethods;
});
