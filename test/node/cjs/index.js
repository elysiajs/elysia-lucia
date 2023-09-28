if ('Bun' in globalThis) {
  throw new Error('❌ Use Node.js to run this test!');
}

const { staticPlugin } = require('@elysiajs/lucia-auth');

if (typeof staticPlugin !== 'function') {
  throw new Error('❌ CommonJS Node.js failed');
}

console.log('✅ CommonJS Node.js works!');
