"use strict";
const Koa = require('koa');
const crypto = require('crypto');
const auth = require('basic-auth');

const app = new Koa();
const router = require('koa-router')();
const koaBody = require('koa-body')();
const DB = require('mongodb-next');

const db = DB('mongodb://localhost/oauth2', {
    w: 'majority'
});

async function basicAuth(ctx, next) {
    const user = auth(ctx);
    const result = await db.collection('clients').find({clientId: user.name, secret: user.pass});

    if (result && result.length === 1) {
        ctx.user = result[0];
        await next();
    } else {
        ctx.status = 401;
    }
}

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

router.post("/register", koaBody, async ctx => {
    if (!ctx.request.body.name || !ctx.request.body.redirect_uri) {
        ctx.status = 400;
        return;
    }

    let client = {
        clientId: crypto.randomBytes(32).toString('hex'),
        secret: crypto.randomBytes(48).toString('hex'),
        name: ctx.request.body.name,
        redirectURI: ctx.request.body.redirect_uri
    };

    const result = await db.collection('clients').insert(client);

    ctx.status = 201;
    ctx.body = JSON.stringify(client);
});

router.get("/authorize", koaBody, async ctx => {
    ctx.status = 302;

    let result = "";
    let redirectURI = ctx.query.redirect_uri || "";
    try {
        if(!ctx.query.response_type  || !ctx.query.client_id) {
            throw "invalid_request";
        }

        if(["code", "token"].indexOf(ctx.query.response_type) < 0) {
            throw "unsupported_response_type";
        }

        let connection = {
            clientId: ctx.query.client_id,
            resourceOwner: ctx.query.username,
            authorization_code: crypto.randomBytes(32).toString('hex')
        };

        const client = await db.collection('clients').findOne({clientId: connection.clientId});

        if (!client) {
            throw "unauthorized_client";
        }

        if(ctx.query.redirect_uri && ctx.query.redirect_uri !==client.redirectURI) {
            throw "invalid_request";
        }
        redirectURI = client.redirectURI;
        if(ctx.query.response_type === "token") {
            connection.tokens = generateTokens(false);
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
        ctx.set('Location', redirectURI + (redirectURI.indexOf("?") < 0 ? "?" : "&") + result);
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

        if (ctx.request.body.redirect_uri !== ctx.user.redirectURI) {
            throw "invalid_request";
        }

        let connection = await db.collection('connections').findOne({authorization_code: ctx.request.body.code});

        if (!connection || connection.clientId !== ctx.user.clientId) {
            throw "invalid_grant";
        }

        delete connection.authorization_code;

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
app.listen(3000);