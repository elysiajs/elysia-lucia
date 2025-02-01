import { Elysia, t, type LocalHook, type CookieOptions } from 'elysia'

import { lucia, type Auth, type Configuration } from 'lucia'

import {
	auth0,
	apple,
	azureAD,
	bitbucket,
	box,
	cognito,
	discord,
	dropbox,
	facebook,
	github,
	gitlab,
	google,
	lichess,
	line,
	linkedIn,
	osu,
	patreon,
	reddit,
	salesforce,
	slack,
	spotify,
	strava,
	twitch,
	twitter
} from '@lucia-auth/oauth/providers'

import {
	createOAuth,
	createOAuthWithPKCE,
	InvalidSession,
	type Prettify
} from './utils'

export interface LuciaConfig<Name extends string, SessionName extends string>
	extends Omit<Configuration, 'env'> {
	name: Name
	session: SessionName
	env?: Configuration['env']
	cookie?: Parameters<typeof t.Cookie>[1]
	key?: string
}

export const Lucia = <
	const Attributes extends Record<
		string,
		unknown
		// @ts-ignore
	> = never extends Lucia.DatabaseUserAttributes
		? Record<
				string,
				unknown
				// @ts-ignore
			>
		: // @ts-ignore
			Lucia.DatabaseUserAttributes,
	const Name extends string = 'user',
	const SessionName extends string = 'session'
>(
	configuration: LuciaConfig<Name, SessionName>
) => {
	const auth = lucia({
		...configuration,
		env:
			(process.env.ENV ?? process.env.NODE_ENV) === 'production'
				? 'PROD'
				: 'DEV'
	})

	const name: Name = configuration.name ?? ('user' as Name)
	const sessionName: SessionName =
		configuration.session ?? ('session' as SessionName)

	const key = configuration.key ?? 'username'

	const {
		maxAge = 60 * 60 * 24 * 30,
		expires = 60 * 60 * 24 * 30,
		sameSite = 'none',
		httpOnly = true,
		path = '/',
		...cookieOptions
	} = configuration.cookie ?? {}

	const elysia = new Elysia({
		name: '@elysiajs/lucia-auth',
		seed: configuration
	})
		.error({
			INVALID_SESSION: InvalidSession
		})
		.derive({ as: 'global' }, function deriveAuth({ cookie }) {
			const session = cookie[sessionName]

			const decorators = {
				auth,
				get id() {
					try {
						return auth
							.getSession(session.value as string)
							.then(({ user: { userId } }) => userId)
					} catch {
						throw new InvalidSession()
					}
				},
				get profile() {
					return decorators.id.then(async (id) =>
						auth.getUser(id)
					) as Promise<Attributes>
				},
				async signUp(
					{
						username,
						password,
						...rest
					}: {
						username: string
						password: string
					} & Partial<Attributes>,
					{
						createSession = false
					}: {
						/**
						 * @default false
						 */
						createSession: boolean
					} = {
						createSession: false
					}
				) {
					const data = await auth.createUser({
						key: {
							providerId: key,
							providerUserId: username,
							password
						},
						attributes: {
							username,
							...rest
						}
					})

					if (createSession)
						await decorators.signIn({
							username,
							password
						})

					return data
				},
				async signIn(user: { username: string; password: string }) {
					const { userId } = await auth.useKey(
						key,
						user.username,
						user.password
					)

					const { sessionId } = await auth.createSession({
						userId,
						attributes: {}
					})

					session.value = sessionId
					session.set({
						maxAge,
						expires:
							expires instanceof Date
								? expires
								: new Date(Date.now() + expires * 1000),
						sameSite,
						httpOnly,
						path,
						...cookieOptions
					})
				},
				async updateUser(
					// @ts-ignore
					attributes: Lucia.DatabaseUserAttributes
				) {
					auth.updateUserAttributes(await decorators.id, attributes)
				},
				async updatePassword(username: string, password: string) {
					const { userId } = await auth.updateKeyPassword(
						key,
						username,
						password
					)

					const { sessionId } = await auth.createSession({
						userId,
						attributes: {}
					})

					session.value = sessionId
				},
				async refresh() {
					const { userId: id, sessionId } = await auth.createSession({
						userId: await decorators.id,
						sessionId: session.value as string,
						attributes: {}
					})

					session.value = sessionId
				},
				async signOut(type?: 'all' | 'unused' | 'current') {
					if (!type)
						await auth.invalidateSession(session.value as string)
					else
						switch (type) {
							case 'all':
								await auth.invalidateAllUserSessions(
									session.value as string
								)
								break

							case 'current':
								await auth.invalidateSession(
									session.value as string
								)
								break

							case 'unused':
								await auth.deleteDeadUserSessions(
									session.value as string
								)
								break
						}

					session.remove()
				},
				async delete({
					confirm
				}: {
					confirm: 'DELETE ALL USER DATA and is not reversible'
				}) {
					await Promise.all([
						auth.deleteUser(await decorators.id),
						auth.invalidateAllUserSessions(session.value as string)
					])

					session.remove()
				},
				async validate() {
					if (!session.value) throw new InvalidSession()

					try {
						await auth.validateSession(session.value as string)
					} catch {
						throw new InvalidSession()
					}
				}
			} as const

			return {
				[name as Name]: decorators
			} as const
		})
		.macro(({ onBeforeHandle }) => {
			return {
				isSignIn(value: boolean) {
					onBeforeHandle(async function checkSession({ cookie }) {
						const session = cookie[sessionName]

						if (!session.value) throw new InvalidSession()

						try {
							await auth.validateSession(session.value as string)
						} catch {
							throw new InvalidSession()
						}
					})
				}
			}
		})

	return {
		lucia: auth,
		elysia,
		oauth: {
			auth0: createOAuth(
				auth,
				auth0,
				'auth0',
				sessionName,
				({ email, sub }) => ({
					id: sub,
					username: email
				})
			),
			apple: createOAuth(
				auth,
				apple,
				'apple',
				sessionName,
				({ email, sub }) => ({
					id: sub,
					username: email
				})
			),
			azure: createOAuthWithPKCE(
				auth,
				azureAD,
				'azureAD',
				sessionName,
				({ email, sub }) => ({
					id: sub,
					username: email
				})
			),
			box: createOAuth(auth, box, 'box', sessionName, ({ id, name }) => ({
				id,
				username: name
			})),
			discord: createOAuth(
				auth,
				discord,
				'discord',
				sessionName,
				({ id, username }) => ({
					id,
					username
				})
			),
			dropbox: createOAuth(
				auth,
				dropbox,
				'dropbox',
				sessionName,
				({ email, name }) => ({
					id: email,
					username: name
				})
			),
			facebook: createOAuth(
				auth,
				facebook,
				'facebook',
				sessionName,
				({ id, name }) => ({
					id,
					username: name
				})
			),
			github: createOAuth(
				auth,
				github,
				'github',
				sessionName,
				({ id, login }) => ({
					id: id.toString(),
					username: login
				})
			),
			gitlab: createOAuth(
				auth,
				gitlab,
				'gitlab',
				sessionName,
				({ id, name }) => ({
					id: id.toString(),
					username: name
				})
			),
			google: createOAuth(
				auth,
				google,
				'google',
				sessionName,
				({ sub, name }) => ({
					id: sub,
					username: name
				})
			),
			lichless: createOAuthWithPKCE(
				auth,
				lichess,
				'lichess',
				sessionName,
				({ id, username }) => ({
					id,
					username
				})
			),
			line: createOAuth(
				auth,
				line,
				'line',
				sessionName,
				({ userId, displayName }) => ({
					id: userId,
					username: displayName
				})
			),
			linkedIn: createOAuth(
				auth,
				linkedIn,
				'linkedIn',
				sessionName,
				({ name, email }) => ({
					id: email,
					username: name
				})
			),
			osu: createOAuth(
				auth,
				osu,
				'osu',
				sessionName,
				({ id, username }) => ({
					id: id.toString(),
					username
				})
			),
			patreon: createOAuth(
				auth,
				patreon,
				'patreon',
				sessionName,
				({ id, attributes: { full_name } }) => ({
					id,
					username: full_name
				})
			),
			reddit: createOAuth(
				auth,
				reddit,
				'reddit',
				sessionName,
				({ id, name }) => ({
					id,
					username: name
				})
			),
			salesforce: createOAuth(
				auth,
				salesforce,
				'salesforce',
				sessionName,
				({ user_id, name }) => ({
					id: user_id,
					username: name
				})
			),
			slack: createOAuth(
				auth,
				slack,
				'slack',
				sessionName,
				({ sub, name }) => ({
					id: sub,
					username: name
				})
			),
			spotify: createOAuth(
				auth,
				spotify,
				'spotify',
				sessionName,
				({ id, display_name }) => ({
					id: id,
					username: display_name
				})
			),
			twitch: createOAuth(
				auth,
				twitch,
				'twitch',
				sessionName,
				({ id, display_name }) => ({
					id,
					username: display_name
				})
			),
			twitter: createOAuthWithPKCE(
				auth,
				twitter,
				'twitter',
				sessionName,
				({ id, name }) => ({
					id: id,
					username: name
				})
			)
		}
	}
}

export default Lucia
