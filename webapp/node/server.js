var cluster = require('cluster');
var numCPUs = require('os').cpus().length;

if (cluster.isMaster) {
  // Fork workers.
  for (var i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', function(worker, code, signal) {
    console.log('worker ' + worker.process.pid + ' died');
  });

  cluster.on('online', function(worker) {
    console.log("worker("+worker.id+").online " + worker.process.pid);
  });
  cluster.on('listening', function(worker, address) {
    console.log("worker("+worker.id+").listening " + address.address + ":" + address.port);
  });

} else {
  var app = require('./app');
  var server = app.listen(process.env.PORT || 8080, function() {
    console.log('Listening on port %d', server.address().port);
  });
}
