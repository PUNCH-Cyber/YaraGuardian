var app = angular.module('yaraGuardian.RuleSearch', [
  'yaraGuardian.API',
  'yaraGuardian.Messages',
  'yaraGuardian.AccountManagement'
]);


app.factory('ruleSearchService', function(apiService, messageService) {

    var searchMethods = {};
    searchMethods.search = {};

    searchMethods.saveSearch = function (newSearch) {
        angular.forEach(newSearch, function (searchContent, searchKey) {
            searchMethods.search[searchKey] = searchContent;
        });
    };

    searchMethods.performSearch = function(groupContext, paramData = {}) {
        messageService.clearMessages();
        apiService.ruleList(groupContext, paramData).then(searchSuccess, searchFailure);
    };

    searchMethods.refreshSearch = function(groupContext) {
        if (angular.isDefined(searchMethods.search.query_params)) {
            var paramData = searchMethods.search.query_params;
            apiService.ruleList(groupContext, paramData).then(searchSuccess, searchFailure);
        };
    };

    searchMethods.getSearchPage = function(pageURL) {
        messageService.clearMessages();
        apiService.getURL(pageURL).then(searchSuccess, searchFailure);
    };

    function searchSuccess(response) {searchMethods.saveSearch(response.data)};
    function searchFailure(response) {console.log(response.data)};

    return searchMethods;
});


app.controller('RuleSearchController', function(accountService, ruleSearchService) {
    var self = this;

    self.search = ruleSearchService.search;

    self.dateFormat = 'yyyy-MM-dd';

    self.show_untagged_rules = false;
    self.show_tagged_rules = false;

    self.sourceFilterOptions = [{'label': 'any', 'display': 'Source', 'search': 'source'}];

    self.categoryFilterOptions = [{'label': 'any', 'display': 'Category', 'search': 'category'}];

    self.submitterFilterOptions = [{'label': 'any', 'display': 'Submitter', 'search': 'submitter'}];

    self.tagFilterOptions = [{'label': 'any', 'display': 'Any Selected Tag', 'search': 'any_tag'},
                             {'label': 'all', 'display': 'All Selected Tags', 'search': 'all_tags'},
                             {'label': 'without', 'display': 'Exclude Selected Tags', 'search': 'without_tag'}];

    self.metakeyFilterOptions = [{'label': 'any', 'display': 'Any Selected Metakey', 'search': 'any_metakey'},
                                 {'label': 'all', 'display': 'All Selected Metakeys', 'search': 'all_metakeys'}];

    self.scopeFilterOptions = [{'label': 'any', 'display': 'Any Selected Scope', 'search': 'any_scope'},
                               {'label': 'all', 'display': 'All Selected Scopes', 'search': 'all_scopes'}];

    self.importFilterOptions = [{'label': 'any', 'display': 'Any Selected Import', 'search': 'any_import'},
                                {'label': 'all', 'display': 'All Selected Imports', 'search': 'all_imports'}];

    self.nameSearchOptions = [{'label': 'contains', 'display': 'Name Contains', 'search': 'name_contains'},
                              {'label': 'startswith', 'display': 'Name Startswith', 'search': 'name_startswith'},
                              {'label': 'endswith', 'display': 'Name Endswith', 'search': 'name_endswith'}];

    self.metakeySearchOptions = [{'label': 'contains', 'display': 'Metakey Name Contains', 'search': 'metakey_contains'},
                                 {'label': 'startswith', 'display': 'Metakey Name Startswith', 'search': 'metakey_startswith'},
                                 {'label': 'endswith', 'display': 'Metakey Name Endswith', 'search': 'metakey_endswith'}];

    self.metadataSearchOptions = [{'label': 'contains', 'display': 'Metadata Content Contains', 'search': 'metavalue_contains'},
                                  {'label': 'startswith', 'display': 'Metadata Content Startswith', 'search': 'metavalue_startswith'},
                                  {'label': 'endswith', 'display': 'Metadata Content Endswith', 'search': 'metavalue_endswith'}];

    self.openCreatedBefore = function() {self.dateInputOpened.created_before=true};
    self.openCreatedAfter = function() {self.dateInputOpened.created_after=true};
    self.openModifiedBefore = function() {self.dateInputOpened.modified_before=true};
    self.openModifiedAfter = function() {self.dateInputOpened.modified_after=true};

    self.performSearch = function(paramData) {
        ruleSearchService.performSearch(accountService.groupContext.name, paramData);
    };

    self.followPage = function(pageUrl) {
        ruleSearchService.getSearchPage(pageUrl);
    };

    self.performFormSearch = function() {
        buildFilters();
        buildSearches();

        if (self.show_untagged_rules === true) {
          self.formData['tagged'] = 'false';
        };

        if (self.show_tagged_rules === true) {
          self.formData['tagged'] = 'true';
        };

        ruleSearchService.performSearch(accountService.groupContext.name, self.formData);
        instantiateForm();
    };

    function instantiateForm() {
        self.formData = {};

        self.dateInputOpened = {'created_before': false,
                                'created_after': false,
                                'modified_before': false,
                                'modified_after': false};

        self.show_untagged_rules = false;
        self.show_tagged_rules = false;

        self.filterValues = {};
        self.filterSelections = {};
        self.filterSelections.source = self.sourceFilterOptions[0];
        self.filterSelections.category = self.categoryFilterOptions[0];
        self.filterSelections.submitter = self.submitterFilterOptions[0];
        self.filterSelections.tag = self.tagFilterOptions[0];
        self.filterSelections.metakey = self.metakeyFilterOptions[0];
        self.filterSelections.scope = self.scopeFilterOptions[0];
        self.filterSelections.import = self.importFilterOptions[0];

        self.searchValues = {};
        self.searchSelections = {};
        self.searchSelections.name = self.nameSearchOptions[0];
        self.searchSelections.metakey = self.metakeySearchOptions[0];
        self.searchSelections.metadata = self.metadataSearchOptions[0];
    };

    function buildSearches() {
        angular.forEach(self.searchValues, function (searchContent, searchName) {
            self.formData[self.searchSelections[searchName].search] = searchContent;
        });
    };

    function buildFilters() {
        angular.forEach(self.filterValues, function (filterContent, filterName) {
            if (filterContent.length > 0) {
                self.formData[self.filterSelections[filterName].search] = filterContent.join();
            };
        });
    };

    instantiateForm()
});
