const auth = require('basic-auth');
const assert = require('assert');

module.exports = function(opts) {
    opts = opts || {};

    assert(opts.db, 'db required');

    return async (ctx, next) => {
        const user = auth(ctx);
        console.log(user);

        const connection = await opts.db.connect;
        const result = await opts.db.collection('clients').find({clientId: user.name, secret: user.pass});

        if (result && result.length === 1) {
            ctx.user = result[0];
            await next();
        } else {
            ctx.status = 401;
        }

    };
};
