"use strict";

const auth = require('basic-auth');

module.exports = function(options) {

    const db = require('mongodb-next')(options.conn, {
        w: 'majority'
    });

    return async function basicAuth(ctx, next) {
        const user = auth(ctx);
        const result = await db.collection('clients').find({client_id: user.name, secret: user.pass});

        if (result && result.length === 1) {
            ctx.user = result[0];
            await next();
        } else {
            ctx.status = 401;
        }
    };
};


