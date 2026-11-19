// Test cases for secrets.yml. Run with: semgrep --test .semgrep/rules
// These tokens are fake and only have the right shape.

// ruleid: hardcoded-socket-api-token
const socketToken = 'sktsec_FAKEFAKEFAKEFAKEFAKEFAKEFAKE_api';
// ok: hardcoded-socket-api-token
const tokenFromEnv = process.env.SOCKET_CLI_API_TOKEN;

// ruleid: hardcoded-generic-secret
const dbPassword = 'Sup3rS3cretValue!';
// ruleid: hardcoded-generic-secret
const config = { apiKey: 'a1b2c3d4e5f6g7h8' };
// ok: hardcoded-generic-secret
const otherPassword = 'changeme-placeholder';
// ok: hardcoded-generic-secret
const shortSecret = 'abc';
// ok: hardcoded-generic-secret
const username = 'administrator';

export { socketToken, tokenFromEnv, dbPassword, config, otherPassword, shortSecret, username };
