var app = angular.module('yaraGuardian.Filters', []);


app.filter('isEmpty', function() {
    return function(object) {
        return angular.equals({}, object);
    };
});


app.filter('contentLength', function () {
  return function (content) {

    if (angular.isDefined(content)) {
        return Object.keys(content).length;
    } else {
        return 0;
    }
  };
});


app.filter('contentRange', function() {
    // http://stackoverflow.com/questions/11873570/angularjs-for-loop-with-numbers-ranges
    return function(input, total) {
        total = parseInt(total);
        total += 1;

        for (var i=1; i < total; i++) {
            input.push(i);
        }

        return input;
    };
});
