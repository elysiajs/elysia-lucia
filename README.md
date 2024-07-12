# Experimental package, DO NOT USE

# @elysiajs/lucia-auth
Plugin for [elysia](https://github.com/saltyaom/elysia) authentication using Lucia

## Installation
```bash
bun add @elysiajs/lucia-auth
```

## Example
```ts
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
                .delete('/profile', async ({ user }) => {
                    await user.delete({
                        'confirm': 'DELETE ALL USER DATA and is not reversible'
                    })

                    return 'Signed out'
                })
                .get('/sign-out', async ({ user }) => {
                    await user.signOut()

                    return 'Signed out'
                })
    )
```
