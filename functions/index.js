// src/index.js
const { app } = require('@azure/functions');

// Import each handler (they must not themselves call app.http)
const { handler: checkAdmin }  = require('./checkAdmin');
const { handler: scoreboard }  = require('./scoreboard');
const { handler: upload }      = require('./upload');
const { handler: users }       = require('./users');

app.http('checkAdmin', {
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: checkAdmin
});

app.http('scoreboard', {
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: scoreboard
});

app.http('upload', {
  methods: ['POST'],
  authLevel: 'anonymous',
  handler: upload
});

app.http('users', {
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: users
});
