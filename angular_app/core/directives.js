var app = angular.module('yaraGuardian.Directives', []);


app.directive('ngFiles', function ($parse) {

    function fn_link(scope, element, attrs) {
        var onChange = $parse(attrs.ngFiles);
        element.on('change', function (event) {
            onChange(scope, { $files: event.target.files });
        });
    };

    return {link: fn_link};
});
