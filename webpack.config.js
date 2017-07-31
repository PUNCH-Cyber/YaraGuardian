const path = require('path');
const webpack = require('webpack');
const CopyWebpackPlugin = require('copy-webpack-plugin');

const JS = [
    'angular/angular.min.js',
    'angular/angular.min.js.map',
    'angular-animate/angular-animate.min.js',
    'angular-animate/angular-animate.min.js.map',
    'angular-ui-bootstrap/dist/ui-bootstrap.js',
    'angular-ui-bootstrap/dist/ui-bootstrap-tpls.js',
    'angular-multiselect/dist/multiselect.js',
    'angular-multiselect/dist/multiselect-tpls.js',
    'angular-file-upload-shim/dist/angular-file-upload.min.js',
    'angular-file-upload-shim/dist/angular-file-upload-shim.min.js',
    'angular-route/angular-route.min.js',
    'angular-route/angular-route.min.js.map',
    'angular-touch/angular-touch.min.js',
    'angular-touch/angular-touch.min.js.map',
    'bootstrap/dist/js/bootstrap.min.js',
    'ng-file-upload/dist/ng-file-upload.min.js',
    'ng-file-upload/dist/ng-file-upload-shim.min.js'
];

const CSS = [
    'angular-ui-bootstrap/dist/ui-bootstrap-csp.css',
    'angular-multiselect/dist/multiselect.css',
    'bootstrap/dist/css/bootstrap.min.css',
    'bootstrap/dist/css/bootstrap.min.css.map'
]

const FONTS = [
    'bootstrap/dist/fonts/'
]

// Create Copying Tasks
var CopyTasks = [];

JS.forEach(function(element) {
  CopyTasks.push({
      from: path.resolve(__dirname, `./node_modules/${element}`),
      to: path.resolve(__dirname, './npm/js/')
  });
});

CSS.forEach(function(element) {
  CopyTasks.push({
      from: path.resolve(__dirname, `./node_modules/${element}`),
      to: path.resolve(__dirname, './npm/css/')
  });
});

FONTS.forEach(function(element) {
  CopyTasks.push({
      from: path.resolve(__dirname, `./node_modules/${element}`),
      to: path.resolve(__dirname, './npm/fonts/')
  });
});

module.exports = {
    entry: {
        app: "./angular_app/app.js",
    },
    output: {
        path: __dirname + "/static/",
        filename: "[name].bundle.js"
    },
    plugins: [
      new CopyWebpackPlugin(CopyTasks)
    ]
};
