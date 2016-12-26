"use strict";
const Koa = require('koa');
const crypto = require('crypto');

const app = new Koa();
const router = require('koa-router')();
const koaBody = require('koa-body')();
const DB = require('mongodb-next');

const db = DB('mongodb://localhost/oauth2', {
    w: 'majority'
});

const basicAuth = require('./modules/basic_auth')({db: db});

router.post("/register", koaBody, async ctx => {
    if(!ctx.request.body.name || !ctx.request.body.redirectURL) {
        ctx.status = 400;
        return;
    }

    let client = {
        clientId: crypto.randomBytes(32).toString('hex'),
        secret: crypto.randomBytes(48).toString('hex'),
        name: ctx.request.body.name,
        redirectURL: ctx.request.body.redirectURL
    };

    const connection = await db.connect;
    const result = await db.collection('clients').insert(client);

    console.log(result);
    ctx.status = 201;
    ctx.body = JSON.stringify(client);

});

// /grant?clientId=.... body username=asdf&secret=3234234
router.get("/grant", koaBody, async ctx => {

    let connection = {
        clientId: ctx.query.clientId,
        resourceOwner: ctx.query.username,
        authorization_code: crypto.randomBytes(32).toString('hex')
    };

    const client = await db.collection('clients').findOne({clientId:connection.clientId});

    if(!client) {
        ctx.status = 400;
        return;
    }

    await db.collection('connections').insert(connection);

    ctx.status=303;
    ctx.set('Location', client.redirectURL + "?code=" + connection.authorization_code);

});


router.post("/token", koaBody, basicAuth, async ctx => {
    if(!ctx.request.body.grant_type || !ctx.request.body.code ||  !ctx.request.body.redirectURL) {
        ctx.status = 400;
        return;
    }

    if(ctx.request.body.grant_type !== "authorization_code") {
        ctx.status = 400;
        return;
    }

    if(ctx.request.body.redirectURL !== ctx.user.redirectURL) {
        ctx.status = 400;
        return;
    }

    let connection  = await db.collection('connections').findOne({authorization_code : ctx.request.body.code});
    if(connection.authorization_code !== ctx.request.body.code || connection.clientId !== ctx.user.clientId) {
        ctx.status = 400;
        return;
    }

    // access token generieren, refresh token generieren, access token timeout setzen
    let tokens = {
        access_token: crypto.randomBytes(32).toString('hex'),
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: crypto.randomBytes(32).toString('hex')
    };
    connection.tokens = tokens;
    const result = await db.collection('connections').findOne(connection._id).update(connection);

    ctx.status = 201;
    ctx.body = JSON.stringify(tokens);

});
// uses async functions
app.use(router.routes());

app.listen(3000);