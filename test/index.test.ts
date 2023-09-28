import { Elysia } from 'elysia'
import { Lucia } from '../src'

import { describe, expect, it } from 'bun:test'

const req = (path: string) => new Request(`http://localhost${path}`)
