import { Elysia, t } from 'elysia'
import { swagger } from '@elysiajs/swagger'

import { Lucia } from '../src/index'
import { prisma as adapter } from '@lucia-auth/adapter-prisma'

import { PrismaClient } from '@prisma/client'

const { GH_CLIENT_ID, GH_CLIENT_SECRET } = process.env

if (!GH_CLIENT_ID || !GH_CLIENT_SECRET)
    throw new Error('GitHub OAuth token is need')

const { elysia, lucia, oauth } = Lucia({
    adapter: adapter(new PrismaClient())
})
    
const auth = new Elysia({ prefix: '/auth' })
    .use(elysia)
    .use(
        oauth.github({
            clientId: GH_CLIENT_ID,
            clientSecret: GH_CLIENT_SECRET
        })
    )
    .guard(
        {
            body: t.Object({
                username: t.String(),
                password: t.String()
            })
        },
        (app) =>
            app
                .put('/sign-up', async ({ body, user }) => user.signUp(body))
                .post(
                    '/sign-in',
                    async ({ user, body: { username, password } }) => {
                        await user.signIn(username, password)

                        return `Sign in as ${username}`
                    }
                )
    )
    .guard(
        {
            beforeHandle: ({ user: { validate } }) => validate()
        },
        (app) =>
            app
                .get('/profile', ({ user }) => user.data)
                .get('/refresh', async ({ user }) => {
                    await user.refresh()

                    return user.data
                })
                .get('/sign-out', async ({ user }) => {
                    await user.signOut()

                    return 'Signed out'
                })
    )

const app = new Elysia()
    .use(elysia)
    .onBeforeHandle(async ({ path, user }) => {
        switch (path) {
            case '/swagger':
            case '/swagger/json':
                await user.validate()
        }
    })
    .use(swagger())
    .use(auth)
    .listen(3000, ({ hostname, port }) => {
        console.log(`Running at http://${hostname}:${port}`)
    })
