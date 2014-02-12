module.exports = function (grunt) {

  grunt.initConfig({
    jshint: {
      all: ['Gruntfile.js', 'webmaker-login.js', 'example/webmaker-auth-client.js'],
      options: {
        jshintrc: '.jshintrc'
      }
    },
    jsbeautifier: {
      modify: {
        src: ['Gruntfile.js', 'webmaker-login.js', 'example/webmaker-auth-client.js'],
        options: {
          config: '.jsbeautifyrc'
        }
      },
      validate: {
        src: ['Gruntfile.js', 'webmaker-login.js', 'example/webmaker-auth-client.js'],
        options: {
          mode: 'VERIFY_ONLY',
          config: '.jsbeautifyrc'
        }
      }
    }
  });

  grunt.loadNpmTasks('grunt-jsbeautifier');
  grunt.loadNpmTasks('grunt-contrib-jshint');

  // Clean code before a commit
  grunt.registerTask('clean', ['jsbeautifier:modify', 'jshint']);

  // Validate code (read only)
  grunt.registerTask('validate', ['jsbeautifier:validate', 'jshint']);

  grunt.registerTask('default', ['jsbeautifier:validate', 'jshint']);
};
