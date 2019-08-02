module.exports = function(config) {
  // bundler to test: webpack, browserify
  const bundler = process.env.BUNDLER || 'webpack';
  const frameworks = ['mocha'];
  const files = ['unit/index.js'];
  const reporters = ['mocha'];
  const browsers = ['ChromeHeadless'];
  const client = {
    mocha: {
      timeout: 2000
    }
  };
  // main bundle preprocessors
  const preprocessors = [];
  preprocessors.push(bundler);
  preprocessors.push('sourcemap');

  return config.set({
    frameworks, files, reporters,
    basePath: '', port: 9876, colors: true,
    browsers, client, singleRun: true,
    // preprocess matching files before serving them to the browser
    // available preprocessors:
    // https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      'unit/*.js': preprocessors,
    },
    webpack: {
      devtool: 'inline-source-map',
      mode: 'development',
      node: {
        Buffer: false,
        crypto: false,
        setImmediate: false
      }
    }
  });
};
