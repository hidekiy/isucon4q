var app = require('./app');

app.tools.loadLoginLog(function (err) {
  if (err) throw err;
  console.log('done init');
  process.exit(0);
});
