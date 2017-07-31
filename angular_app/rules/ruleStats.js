var app = angular.module('yaraGuardian.RuleStats', [
    'yaraGuardian.API',
    'yaraGuardian.Services',
    'yaraGuardian.AccountManagement'
]);


app.factory('ruleStatService', function(apiService, coreServices) {

    var statMethods = {};
    statMethods.stats = {};
    statMethods.loading = false;
    statMethods.panelDisplays = {};

    statMethods.retrieveStats = function(groupName, params = {}) {
        statMethods.loading = true;
        apiService.ruleStats(groupName, params).then(statRetrieveSuccess, statRetrieveFailure);
    };

    function statRetrieveSuccess(response) {
        coreServices.refreshObject(statMethods.stats, response.data);
        statMethods.panelDisplays.tags = buildStatPages(statMethods.stats.tag_count, 15);
        statMethods.panelDisplays.metakeys = buildStatPages(statMethods.stats.metakey_count, 15);
        statMethods.loading = false;
    };

    function statRetrieveFailure(response) {
        statMethods.loading = false;
    };

    function buildStatPages(statObj, pageSize) {
        var entryCount = Object.keys(statObj).length;
        var maxPage = Math.ceil(entryCount / pageSize);
        var currentPage = 1;
        var statContent = [];
        var statPages = {};

        Object.getOwnPropertyNames(statObj).forEach(function(val, idx, array) {
            statContent.push([val, statObj[val]]);
        });

        var pageCounter = 1;
        var entryCounter = 0;

        while (pageCounter <= maxPage) {
            statPages[pageCounter] = statContent.slice(entryCounter, entryCounter + pageSize);
            pageCounter = pageCounter + 1;
            entryCounter = entryCounter + pageSize;
        };

        var newStatObj = {};
        newStatObj.maxPage = maxPage;
        newStatObj.currentPage = currentPage;
        newStatObj.entryCount = entryCount;
        newStatObj.pageEntries = statPages;

        return newStatObj;
    };

    return statMethods;
});


app.controller('RuleStatsController', function(accountService, ruleStatService) {

    var self = this;

    self.stats = ruleStatService.stats;
    self.loading = ruleStatService.loading;
    self.panelDisplays = ruleStatService.panelDisplays;

    self.retrieveStats = function() {
        ruleStatService.retrieveStats(accountService.groupContext.name);
    };

    self.changeTagDisplayPage = function(page) {
        var lastPage = self.panelDisplays.tags.maxPage;

        if (page < 1) {
            self.panelDisplays.tags.currentPage = lastPage;
        } else if (page > lastPage) {
            self.panelDisplays.tags.currentPage = 1;
        } else {
            self.panelDisplays.tags.currentPage = page;
        };
    };

    self.changeMetakeyDisplayPage = function(page) {
      var lastPage = self.panelDisplays.metakeys.maxPage;

      if (page < 1) {
          self.panelDisplays.metakeys.currentPage = lastPage;
      } else if (page > lastPage) {
          self.panelDisplays.metakeys.currentPage = 1;
      } else {
          self.panelDisplays.metakeys.currentPage = page;
      };
    };
});
