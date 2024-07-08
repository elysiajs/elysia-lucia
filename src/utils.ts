import { Elysia, type LocalHook } from 'elysia'

import { type lucia } from 'lucia'

import type { CookieOptions } from 'elysia'
import type {
    OAuth2ProviderAuth,
    OAuth2ProviderAuthWithPKCE
} from '@lucia-auth/oauth'

export type Prettify<T extends Record<string, unknown>> = {
    [K in keyof T]: T[K]
}

type MaybePromise<T> = T | Promise<T>

export const createOAuth =
    <
        Name extends string,
        const AuthConstructor extends (...a: any[]) => OAuth2ProviderAuth
    >(
        auth: ReturnType<typeof lucia>,
        createProvider: AuthConstructor,
        name: Name,
        sessionName: string,
        defaultCreateUser: (
            // @ts-ignore
            user: Awaited<
                ReturnType<ReturnType<AuthConstructor>['validateCallback']>
            >[`${Name}User`]
        ) => MaybePromise<
            Record<string, unknown> & {
                id: string | number
            }
        >
    ) =>
    <
        const Path extends string = `/${Name}`,
        const Callback extends string = `${Path}/callback`
    >(
        config: Prettify<
            Parameters<AuthConstructor>[1] & {
                path?: Path
                callback?: Callback
                createUser?: (
                    // @ts-ignore
                    user: Awaited<
                        ReturnType<
                            ReturnType<AuthConstructor>['validateCallback']
                        >
                    >[`${Name}User`]
                ) => MaybePromise<
                    Record<string, unknown> & {
                        id: string | number
                    }
                >
                hook?: {
                    redirect?: LocalHook<any, any, any, any, any, any, any>
                    callback?: LocalHook<any, any, any, any, any, any, any>
                }
                cookie?: {
                    state?: CookieOptions
                    session?: CookieOptions
                }
            }
        >
    ) => {
        const {
            path = `/${name}`,
            callback = `/${name}/callback`,
            createUser: createNewUser = defaultCreateUser,
            hook = {},
            cookie,
            ...init
        } = config

        const provider = createProvider(auth, init)

        return new Elysia({
            name: `@elysiajs/lucia-auth/${name}`,
            seed: config
        })
            .get(
                path,
                async ({ cookie: { oauthState }, set }) => {
                    const [url, state] = await provider.getAuthorizationUrl()

                    oauthState.value = state
                    oauthState.set({
                        path: '/',
                        sameSite: true,
                        httpOnly: true,
                        maxAge: 3600
                    })

                    set.redirect = url.toString()
                },
                // @ts-ignore
                hook.redirect
            )
            .get(
                callback,
                async ({
                    set,
                    query,
                    query: { code, state },
                    cookie,
                    cookie: { oauthState }
                }) => {
                    console.log(state, oauthState.value)

                    if (state !== oauthState.value)
                        throw new Error('Invalid state')

                    const callback = await provider.validateCallback(
                        code as string
                    )

                    const { getExistingUser, createUser, createKey } = callback

                    // @ts-ignore
                    const userData = callback[`${name}User`]

                    const handleCreateUser = async () => {
                        // @ts-ignore
                        const { id, ...attributes } = await createNewUser(
                            userData
                        )

                        await createUser({
                            // @ts-ignore
                            id,
                            attributes
                        })

                        return {
                            userId: id,
                            ...attributes
                        }
                    }

                    const user =
                        (await getExistingUser()) ?? (await handleCreateUser())

                    if (!user?.userId)
                        return (set.status = 'Internal Server Error')

                    const { sessionId } = await auth.createSession({
                        userId: user.userId,
                        attributes: {}
                    })

                    cookie[sessionName].value = sessionId
                    oauthState.remove()

                    return userData
                },
                // @ts-ignore
                hook.callback
            )
    }

export const createOAuthWithPKCE =
    <
        Name extends string,
        const AuthConstructor extends (
            ...a: any[]
        ) => OAuth2ProviderAuthWithPKCE
    >(
        auth: ReturnType<typeof lucia>,
        createProvider: AuthConstructor,
        name: Name,
        sessionName: string,
        defaultCreateUser?: (
            // @ts-ignore
            user: Awaited<
                ReturnType<ReturnType<AuthConstructor>['validateCallback']>
            >[`${Name}User`]
        ) => MaybePromise<
            Record<string, unknown> & {
                id: string | number
            }
        >
    ) =>
    <
        const Path extends string = `/${Name}`,
        const Callback extends string = `${Path}/callback`
    >(config: {
        path?: Path
        callback?: Callback
        createUser?: (
            // @ts-ignore
            user: Awaited<
                ReturnType<ReturnType<AuthConstructor>['validateCallback']>
            >[`${Name}User`]
        ) => MaybePromise<
            Record<string, unknown> & {
                id: string | number
            }
        >
        hook?: {
            redirect?: LocalHook<any, any, any, any, any, any, any>
            callback?: LocalHook<any, any, any, any, any, any, any>
        }
        cookie?: {
            state?: CookieOptions
            session?: CookieOptions
        }
        config: Parameters<AuthConstructor>[1]
    }) => {
        const {
            path = `/${name}`,
            callback = `/${name}/callback`,
            hook = {},
            createUser: createNewUser = defaultCreateUser,
            ...init
        } = config

        const provider = createProvider(auth, init)

        return new Elysia({
            name: `@elysiajs/lucia-auth/${name}`,
            seed: config
        })
            .get(
                path,
                async ({ cookie: { oauthState, oauthVerifier }, redirect, set }) => {
                    const [url, verifier, state] =
                        await provider.getAuthorizationUrl()

                    oauthVerifier.set({
                        value: verifier,
                        path: '/',
                        sameSite: true,
                        httpOnly: true,
                        maxAge: 3600
                    })

                    oauthState.set({
                        value: state,
                        path: '/',
                        sameSite: true,
                        httpOnly: true,
                        maxAge: 3600
                    })

                    return redirect(url.toString())
                },
                hook.redirect
            )
            .get(
                callback,
                async ({
                    set,
                    query,
                    query: { code, state },
                    cookie,
                    cookie: { oauthState, oauthVerifier }
                }) => {
                    if (state !== oauthState.value)
                        throw new Error('Invalid state')

                    if (state !== oauthVerifier.value)
                        throw new Error('Invalid oauth verifier')

                    const callback = await provider.validateCallback(
                        code as string,
                        oauthVerifier.value as string
                    )

                    const { getExistingUser, createUser, createKey } = callback

                    // @ts-ignore
                    const userData = callback[`${name}User`]

                    const handleCreateUser = async () => {
                        // @ts-ignore
                        const { id, ...attributes } = await createNewUser(
                            userData
                        )

                        await createUser({
                            // @ts-ignore
                            id,
                            attributes
                        })

                        return {
                            userId: id,
                            ...attributes
                        }
                    }

                    const user =
                        (await getExistingUser()) ?? (await handleCreateUser())

                    if (!user?.userId)
                        return (set.status = 'Internal Server Error')

                    const { sessionId } = await auth.createSession({
                        userId: user.userId,
                        attributes: {}
                    })

                    cookie[sessionName].value = sessionId
                    oauthState.remove()

                    return userData
                },
                // @ts-ignore
                hook.callback
            )
    }

export class InvalidSession extends Error {
    status = 401

    constructor(public message = 'Unauthorized') {
        super(message)
    }
}
