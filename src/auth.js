/** ************************************************************************
 *  (C) Copyright Mojaloop Foundation 2020                                *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha <yevhen.kyriukha@modusbox.com>                   *
 ************************************************************************* */

/**
 * Keto auth middleware for Koa
 */

const { RelationshipApi, PermissionApi } = require('@ory/keto-client');

module.exports.createAuthMiddleware = (userIdHeader, oryKetoReadUrl, oryKratosReadUrl) => {
    const RelationshipApiObj = new RelationshipApi(undefined, oryKetoReadUrl);
    const PermissionApiObj = new PermissionApi(undefined, oryKetoReadUrl);

    // const opts = {
    //     validateStatus: () => true,
    // };

    // const getParticipantsByUserId = async (userId) => {
    //     const response = await oryKetoReadApi.getRelationTuples('participant', undefined, 'member', userId);
    //     return response.data.relation_tuples.map(({ object }) => object);
    // };

    const getParticipantsByUserId = async (userId) => {
        const response = await RelationshipApiObj.getRelationships({
            namespace: "participant",
            relation: "member",
            subjectId: userId,
        });
        return response.data.relation_tuples.map(({ object }) => object);
    };

    // const canAccessReport = async (userId, obj) => {
    //     const response = await oryKetoReadApi.getCheck('permission', obj, 'granted', userId, opts);
    //     return response.data.allowed;
    // };

    const canAccessReport = async (userId, obj) => {
        const response = await PermissionApiObj.checkPermission({
            namespace: "permission",
            object: obj,
            relation: "granted",
            subjectId: userId,
        });
        return response.data.allowed;
    };

    const canAccessParticipant = (ctx) => Object.entries(ctx.request.query)
        .filter(([k]) => /^d?fspId$/i.test(k))
        .map(([, fspId]) => ctx.state.participants.includes(fspId))
        .every(Boolean);

    return async (ctx, next) => {
        // Call kraots whoami api using session token to authenticate the user
        const token = ctx.req.headers[userIdHeader];
        const authResp = await fetch(`${oryKratosReadUrl}/sessions/whoami`, {
            headers: {
                cookie: token
            }
        });

        if (!authResp.ok) {
            ctx.response.status = 401;
            return;
        }

        const data = await authResp.json();
        const userId = data.identity?.traits?.subject;

        // Then call Keto apis to check the permissions
        ctx.state.participants = await getParticipantsByUserId(userId);
        const obj = ctx.state.reportData.pathMap[ctx.request.URL.pathname.toLowerCase()];
        if (!obj) {
            ctx.response.status = 404;
            return;
        }
        const grants = await Promise.all([
            canAccessReport(userId, obj),
            canAccessParticipant(ctx),
        ]);
        if (grants.every(Boolean)) {
            await next();
        } else {
            ctx.response.status = 403;
        }
    };
};
