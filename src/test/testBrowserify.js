import run from 'tape-run'
import browserify from 'browserify'

browserify('./lib/unitTests.js')
  .bundle()
  .pipe(run())
  .on('results', console.log)
  .pipe(process.stdout)

/*import run from 'browserify-test'

run({
  watch: false,
  transform: ['brfs', ['babelify', { presets: 'es2015' }]],
  files: ['./lib/unitTests.js'],
})*/