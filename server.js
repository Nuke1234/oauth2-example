"use strict";

const connection = 'mongodb://mongo:27017/oauth2';

const app = new (require('koa'))({conn : connection});
const crypto = require('crypto');
const router = require('koa-router')();
const koaBody = require('koa-body')();

const DB = require('mongodb-next');

const db = DB(connection, {w: 'majority'});


const basicAuth = require("./modules/mongo-basic-auth")(connection);

function generateTokens(generateRefreshToken = true) {
    let tokens = {
        access_token: crypto.randomBytes(32).toString('hex'),
        token_type: "Bearer",
        expires_in: 3600
    };

    if(generateRefreshToken) {
        tokens.refresh_token = crypto.randomBytes(32).toString('hex');
    }
    return tokens;
}
//the router
router.post("/register", koaBody, async ctx => {
    if (!ctx.request.body.name || !ctx.request.body.redirect_uri) {
        ctx.status = 400;
        return;
    }

    let client = {
        client_id: crypto.randomBytes(32).toString('hex'),
        secret: crypto.randomBytes(48).toString('hex'),
        name: ctx.request.body.name,
        redirect_uri: ctx.request.body.redirect_uri
    };

    const result = await db.collection('clients').insert(client);

    ctx.set('Content-Type', 'application/json;charset=utf-8');
    ctx.status = 201;
    ctx.body = JSON.stringify(client);

});

router.get("/authorize", koaBody, async ctx => {
    ctx.status = 302;

    let result = "";
    let redirect_uri = ctx.query.redirect_uri || "";
    try {
        if(!ctx.query.response_type  || !ctx.query.client_id) {
            throw "invalid_request";
        }

        if(["code", "token"].indexOf(ctx.query.response_type) < 0) {
            throw "unsupported_response_type";
        }

        let connection = {
            client_id: ctx.query.client_id,
            resourceOwner: ctx.query.username,
        };

        const client = await db.collection('clients').findOne({client_id: connection.client_id});

        if (!client) {
            throw "unauthorized_client";
        }

        if(ctx.query.redirect_uri && ctx.query.redirect_uri !== client.redirect_uri) {
            throw "invalid_request";
        }
        redirect_uri = client.redirect_uri;
        if(ctx.query.response_type === "token") {
            connection.tokens = generateTokens(false);
        } else {
            connection.authorization_code = crypto.randomBytes(32).toString('hex');
            connection.authorization_code_expires_in = new Date(Date.now() + 3600*24*30);
        }

        await db.collection('connections').insert(connection);

        if(ctx.query.response_type === "token") {
            result = `access_token=${connection.tokens.access_token}&token_type=${connection.tokens.token_type}&expires_in=${connection.tokens.expires_in}`;
        } else {
            result = `code=${connection.authorization_code}`;
        }

    } catch(ex) {
        let error = ex;
        if(["unsupported_response_type", "unauthorized_client", "invalid_request"].indexOf(ex) < 0) {
            error = "server_error";
        }
        result = `error=${error}`;
    } finally {
        if(ctx.query.state) {
            result += `&state=${ctx.query.state}`;
        }
        ctx.set('Location', redirect_uri + (redirect_uri.indexOf("?") < 0 ? "?" : "&") + result);
    }
});

router.post("/token", koaBody, basicAuth, async ctx => {
    ctx.set('Content-Type', 'application/json;charset=UTF-8');
    ctx.set('Cache-Control', 'no-store');
    ctx.set('Pragma', 'no-cache');

    try {
        if (!ctx.request.body.grant_type || !ctx.request.body.code || !ctx.request.body.redirect_uri) {
            throw "invalid_request";
        }

        if(ctx.request.body.grant_type !== "authorization_code") {
            throw "unsupported_grant_type";
        }

        if (ctx.request.body.redirect_uri !== ctx.user.redirect_uri) {
            throw "invalid_request";
        }

        let connection = await db.collection('connections').findOne({authorization_code: ctx.request.body.code});

        if (!connection || connection.client_id !== ctx.user.client_id) {
            throw "invalid_grant";
        }

        if(connection.authorization_code_expires_in < Date.now()) {
            await db.collection('connections').findOne(connection._id).remove();
            throw "invalid_grant";
        }

        delete connection.authorization_code;
        delete connection.authorization_code_expires_in;

        connection.tokens = generateTokens();

        await db.collection('connections').findOne(connection._id).update(connection);

        ctx.status = 200;
        ctx.body = JSON.stringify(connection.tokens);
    } catch(ex) {
        let error = ex;
        if(["unsupported_grant_type", "invalid_request", "invalid_grant"].indexOf(ex) < 0) {
            error = "invalid_request";
        }
        ctx.status = 400;
        ctx.body = JSON.stringify({error:error});
    }
});


app.use(router.routes());
app.listen(process.env.NODE_PORT);
