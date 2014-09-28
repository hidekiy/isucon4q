var _ = require('underscore');
var async = require('async');
var bodyParser = require('body-parser');
var crypto = require('crypto');
var ect = require('ect');
var express = require('express');
var logger = require('morgan');
var mysql = require('mysql');
var path = require('path');
var session = require('express-session');
var strftime = require('strftime');

var cluster = require('cluster');
var MemcachedStore = require('connect-memcached')(session);

var app = express();

var globalConfig = {
  userLockThreshold: process.env.ISU4_USER_LOCK_THRESHOLD || 3,
  ipBanThreshold: process.env.ISU4_IP_BAN_THRESHOLD || 10
};

var debug = false;

var mysqlPool = mysql.createPool({
  host: process.env.ISU4_DB_HOST || 'localhost',
  user: process.env.ISU4_DB_USER || 'root',
  password: process.env.ISU4_DB_PASSWORD || '',
  database: process.env.ISU4_DB_NAME || 'isu4_qualifier'
});


var userById = {};
var userByLogin = {};
function loadAllUser(done) {
  mysqlPool.query('SELECT * FROM users', function (err, rows) {
    if (err) return done(err);
    rows.forEach(function (row) {
      userById[row.id] = row;
      userByLogin[row.login] = row;
    });
    console.log('loadAllUser: users: ' + rows.length);
    done(null);
  });
}

var banIp = {};
function loadAllBanIp(done) {
  mysqlPool.query('SELECT * FROM ban_ip', function (err, rows) {
    if (err) return done(err);
    rows.forEach(function (row) {
      banIp[row.ip] = row;
      delete row.ip;
    });
    if (debug) console.log('loadAllBanIp: ips: ' + rows.length);
    done(null);
  });
}

var banUser = {};
function loadAllBanUser(done) {
  mysqlPool.query('SELECT * FROM ban_user', function (err, rows) {
    if (err) return done(err);
    rows.forEach(function (row) {
      banUser[row.user_id] = row;
      delete row.user_id;
    });
    if (debug) console.log('loadAllBanUser: ips: ' + rows.length);
    done(null);
  });
}

function applyBanUser(succeeded, userId, done) {
  if (!userId) return done();

  if (succeeded) {
    if (debug) console.log('reset ban_user failure count');
    mysqlPool.query(
      'INSERT INTO ban_user' +
      ' (`user_id`, `failures`)' +
      ' VALUES (?, 0)' +
      ' ON DUPLICATE KEY UPDATE `failures` = 0',
      [userId],
      done
    );
  } else {
    if (debug) console.log('increment ban_user failure count');
    mysqlPool.query(
      'INSERT INTO ban_user' +
      ' (`user_id`, `failures`)' +
      ' VALUES (?, 1)' +
      ' ON DUPLICATE KEY UPDATE `failures` = `failures` + 1',
      [userId],
      done
    );
  }
}

function applyBanIp(succeeded, ip, done) {
  if (succeeded) {
    if (debug) console.log('reset ban_ip failure count');
    mysqlPool.query(
      'INSERT INTO ban_ip' +
      ' (`ip`, `failures`)' +
      ' VALUES (?, 0)' +
      ' ON DUPLICATE KEY UPDATE `failures` = 0',
      [ip],
      done
    );
  } else {
    if (debug) console.log('increment ban_ip failure count');
    mysqlPool.query(
      'INSERT INTO ban_ip' +
      ' (`ip`, `failures`)' +
      ' VALUES (?, 1)' +
      ' ON DUPLICATE KEY UPDATE `failures` = `failures` + 1',
      [ip],
      done
    );
  }
}

function getLastLogin(userId, done) {
  mysqlPool.query(
    'SELECT * FROM last_login WHERE `user_id` = ?',
    [userId],
    function (err, rows) {
      done(rows ? rows[0] : null);
    }
  );
}

function updateLastLogin(succeeded, userId, ip, done) {
  if (!succeeded) return done();

  mysqlPool.query(
    'INSERT INTO last_login' +
    ' (`user_id`, `created_at`, `ip`)' +
    ' VALUES (?, ?, ?)' +
    ' ON DUPLICATE KEY UPDATE `created_at` = VALUES(`created_at`), `ip` = VALUES(`ip`)',
    [userId, new Date(), ip],
    done
  );
}

function loadLoginLog(done) {
  mysqlPool.query('SELECT * FROM login_log ORDER BY id', function (err, rows) {
    if (err) return done(err);

    async.mapSeries(rows, function (row, done) {
      var succeeded = row.succeeded;
      var userId = row.user_id;
      var ip = row.ip;

      async.parallel([
        function (done) {
          applyBanUser(succeeded, userId, done);
        },
        function (done) {
          applyBanIp(succeeded, ip, done);
        },
        function (done) {
          updateLastLogin(succeeded, userId, ip, done);
        },
      ], done);
    }, function (err) {
      console.log('loadLoginLog: rows: ' + rows.length);
      done(err);
    });
  });
}

app.tools = {
  loadLoginLog: loadLoginLog,
};

app.initialize = function (done) {
  async.parallel([
    loadAllUser,
    loadAllBanIp
  ], done);
};


var helpers = {
  calculatePasswordHash: function(password, salt) {
    var c = crypto.createHash('sha256');
    c.update(password + ':' + salt);
    return c.digest('hex');
  },

  isUserLocked: function(user, callback) {
    if(!user) {
      return callback(false);
    };

    mysqlPool.query(
      'SELECT * FROM ban_user WHERE ' +
      'user_id = ?',
      [user.id],
      function(err, rows) {
        if(err) {
          return callback(false);
        }

        var failures = rows[0] ? rows[0].failures : 0;
        callback(globalConfig.userLockThreshold <= failures);
      }
    );
  },

  isIPBanned: function(ip, callback) {
    if (banIp[ip] && (globalConfig.ipBanThreshold <= banIp[ip].failures)) {
      return callback(true);
    }
    mysqlPool.query(
      'SELECT * FROM ban_ip WHERE ' +
      'ip = ?',
      [ip],
      function(err, rows) {
        if(err) {
          return callback(false);
        }

        var failures = rows[0] ? rows[0].failures : 0;
        callback(globalConfig.ipBanThreshold <= failures);
      }
    )
  },

  attemptLogin: function(req, callback) {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var login = req.body.login;
    var password = req.body.password;

    req.ip = ip;

    async.waterfall([
      function(cb) {
        cb(null, userByLogin[login]);
      },
      function(user, cb) {
        var error = null;
        async.parallel([
          function(done) {
            helpers.isIPBanned(ip, function(banned) {
              if(banned) {
                error = 'banned';
              }
              done(null);
            });
          },
          function (done) {
            helpers.isUserLocked(user, function(locked) {
              if(locked) {
                error = error || 'locked';
              }
              done(null);
            });
          }
        ], function() {
          cb(error, user);
        });
      },
      function(user, cb) {
        if(user && helpers.calculatePasswordHash(password, user.salt) == user.password_hash) {
          cb(null, user);
        } else if(user) {
          cb('wrong_password', user);
        } else {
          cb('wrong_login', user);
        };
      }
    ], function(err, user) {
      var succeeded = !err;
      var userId = (user || {})['id'];

      async.parallel([
        function (done) {
          applyBanUser(succeeded, userId, done);
        },
        function (done) {
          applyBanIp(succeeded, ip, done);
        },
      ], function (e, results) {
        if (e) console.log('attemptLogin: ' + e);
        callback(err, user);
      })
    });
  },

  getCurrentUser: function(user_id, callback) {
    callback(userById[user_id]);
  },

  getBannedIPs: function(callback) {
    mysqlPool.query(
      'SELECT ip' +
      ' FROM ban_ip' +
      ' WHERE failures >= ?' +
      ' ORDER BY ip',
      [globalConfig.ipBanThreshold],
      function(err, rows) {
        callback(_.map(rows, function(row) {
          return row['ip'];
        }));
      }
    );
  },

  getBannedIPsOriginal: function(callback) {
    mysqlPool.query(
      'SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM '+
      'login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?',
      [globalConfig.ipBanThreshold],
      function(err, rows) {
        var bannedIps = _.map(rows, function(row) { return row.ip; });

        mysqlPool.query(
          'SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip',
          function(err, rows) {
            async.parallel(
              _.map(rows, function(row) {
                return function(cb) {
                  mysqlPool.query(
                    'SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id',
                    [row.ip, row.last_login_id],
                    function(err, rows) {
                      if(globalConfig.ipBanThreshold <= (rows[0] || {})['cnt']) {
                        bannedIps.push(row['ip']);
                      }
                      cb(null);
                    }
                  );
                };
              }),
              function(err) {
                callback(bannedIps);
              }
            );
          }
        );
      }
    )
  },

  getLockedUsers: function(callback) {
    mysqlPool.query(
      'SELECT ban_user.user_id, users.login' +
      ' FROM ban_user, users' +
      ' WHERE failures >= ? AND ban_user.user_id = users.id' +
      ' ORDER BY ban_user.user_id',
      [globalConfig.userLockThreshold],
      function(err, rows) {
        callback(_.map(rows, function(row) {
          return row['login'];
        }));
      }
    );
  },

  getLockedUsersOriginal: function(callback) {
    mysqlPool.query(
      'SELECT user_id, login FROM ' +
      '(SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM ' +
      'login_log GROUP BY user_id) AS t0 WHERE t0.user_id IS NOT NULL AND ' +
      't0.max_succeeded = 0 AND t0.cnt >= ?',
      [globalConfig.userLockThreshold],
      function(err, rows) {
        var lockedUsers = _.map(rows, function(row) { return row['login']; });

        mysqlPool.query(
          'SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE ' +
          'user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id',
          function(err, rows) {
            async.parallel(
              _.map(rows, function(row) {
                return function(cb) {
                  mysqlPool.query(
                    'SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id',
                    [row['user_id'], row['last_login_id']],
                    function(err, rows) {
                      if(globalConfig.userLockThreshold <= (rows[0] || {})['cnt']) {
                        lockedUsers.push(row['login']);
                      };
                      cb(null);
                    }
                  );
                };
              }),
              function(err) {
                callback(lockedUsers);
              }
            );
          }
        );
      }
    )
  }
};

if (debug) {
  app.use(logger('dev'));
}
app.enable('trust proxy');
app.engine('ect', ect({ cache: true, root: __dirname + '/views', ext: '.ect' }).render);
app.set('view engine', 'ect');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  'secret': 'isucon4-node-qualifier',
  resave: false,
  saveUninitialized: false,
  store: new MemcachedStore({
    hosts: ['127.0.0.1:11211']
  })
}));
app.use(express.static(path.join(__dirname, '../public')));

app.locals.strftime = function(format, date) {
  return strftime(format, date);
};

app.get('/', function(req, res) {
  var notice = req.session.notice;
  req.session.notice = null;

  res.render('index', { 'notice': notice });
});

app.post('/login', function(req, res) {
  helpers.attemptLogin(req, function(err, user) {
    if(err) {
      switch(err) {
        case 'locked':
          req.session.notice = 'This account is locked.';
          break;
        case 'banned':
          req.session.notice = "You're banned.";
          break;
        default:
          req.session.notice = 'Wrong username or password';
          break;
      }

      return res.redirect('/');
    }

    getLastLogin(user.id, function (lastLogin) {
      req.session.lastLogin = lastLogin || user;
      req.session.userId = user.id;

      updateLastLogin(1, user.id, req.ip, function () {
        res.redirect('/mypage');
      });
    });
  });
});

app.get('/mypage', function(req, res) {
  helpers.getCurrentUser(req.session.userId, function(user) {
    if(!user) {
      req.session.notice = "You must be logged in"
      return res.redirect('/')
    }
    res.render('mypage', { 'last_login': req.session.lastLogin });
  });
});

app.get('/report_orig', function(req, res) {
  async.parallel({
    banned_ips: function(cb) {
      helpers.getBannedIPsOriginal(function(ips) {
        cb(null, ips);
      });
    },
    locked_users: function(cb) {
      helpers.getLockedUsersOriginal(function(users) {
        cb(null, users);
      });
    }
  }, function(err, result) {
    res.json(result);
  });
});

app.get('/report', function(req, res) {
  async.parallel({
    banned_ips: function(cb) {
      helpers.getBannedIPs(function(ips) {
        cb(null, ips);
      });
    },
    locked_users: function(cb) {
      helpers.getLockedUsers(function(users) {
        cb(null, users);
      });
    }
  }, function(err, result) {
    res.json(result);
  });
});

app.use(function (err, req, res, next) {
  res.status(500).send('Error: ' + err.message);
});


if (!module.parent) {
  app.initialize(function (err) {
    if (err) throw err;

    var server = app.listen(process.env.PORT || 8080, function() {
      console.log('app.js: Listening on port %d', server.address().port);
    });
  });
}

module.exports = app;
