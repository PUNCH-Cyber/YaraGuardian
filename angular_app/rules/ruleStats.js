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

    statMethods.sortStat = function(statType, sortType) {
      if (statType === 'tags') {
        statMethods.panelDisplays.tags = buildStatPages(statMethods.stats.tag_count, 15, sortType);
      } else if (statType === 'metakeys') {
        statMethods.panelDisplays.metakeys = buildStatPages(statMethods.stats.metakey_count, 15, sortType);
      }
    };

    function statRetrieveSuccess(response) {
        coreServices.refreshObject(statMethods.stats, response.data);
        statMethods.sortStat('tags', 'nameForward');
        statMethods.sortStat('metakeys', 'nameForward');
        statMethods.loading = false;
    }

    function statRetrieveFailure(response) {
        statMethods.loading = false;
    }

    function buildStatPages(statObj, pageSize, sortType) {
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

        if (sortType === 'nameForward') {
          statContent.sort(function(a, b) {
            return a[0] > b[0] ? 1 : -1;
          });

        } else if (sortType === 'nameBackward') {
          statContent.sort(function(a, b) {
            return a[0] > b[0] ? 1 : -1;
          }).reverse();

        } else if (sortType === 'countForward') {
          statContent.sort(function(a, b) {
            return a[1] > b[1] ? 1 : -1;
          });

        } else if (sortType === 'countBackward') {
          statContent.sort(function(a, b) {
            return a[1] > b[1] ? 1 : -1;
          }).reverse();
        }

        while (pageCounter <= maxPage) {
            statPages[pageCounter] = statContent.slice(entryCounter, entryCounter + pageSize);
            pageCounter = pageCounter + 1;
            entryCounter = entryCounter + pageSize;
        }

        var newStatObj = {};
        newStatObj.maxPage = maxPage;
        newStatObj.currentPage = currentPage;
        newStatObj.entryCount = entryCount;
        newStatObj.pageEntries = statPages;

        return newStatObj;
    }

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

    // Tags Sorting
    self.sortTagsAlpha = function() {
      ruleStatService.sortStat('tags', 'nameForward');
    };
    self.sortTagsRevAlpha = function() {
      ruleStatService.sortStat('tags', 'nameBackward');
    };
    self.sortTagsCount = function() {
      ruleStatService.sortStat('tags', 'countForward');
    };
    self.sortTagsRevCount = function() {
      ruleStatService.sortStat('tags', 'countBackward');
    };

    // Metakeys Sorting
    self.sortMetakeysAlpha = function() {
      ruleStatService.sortStat('metakeys', 'nameForward');
    };
    self.sortMetakeysRevAlpha = function() {
      ruleStatService.sortStat('metakeys', 'nameBackward');
    };
    self.sortMetakeysCount = function() {
      ruleStatService.sortStat('metakeys', 'countForward');
    };
    self.sortMetakeysRevCount = function() {
      ruleStatService.sortStat('metakeys', 'countBackward');
    };

    self.changeTagDisplayPage = function(page) {
        var lastPage = self.panelDisplays.tags.maxPage;

        if (page < 1) {
            self.panelDisplays.tags.currentPage = lastPage;
        } else if (page > lastPage) {
            self.panelDisplays.tags.currentPage = 1;
        } else {
            self.panelDisplays.tags.currentPage = page;
        }
    };

    self.changeMetakeyDisplayPage = function(page) {
      var lastPage = self.panelDisplays.metakeys.maxPage;

      if (page < 1) {
          self.panelDisplays.metakeys.currentPage = lastPage;
      } else if (page > lastPage) {
          self.panelDisplays.metakeys.currentPage = 1;
      } else {
          self.panelDisplays.metakeys.currentPage = page;
      }
    };
});
