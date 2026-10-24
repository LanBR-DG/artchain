# Security status

ArtChain is an educational prototype. There has been no independent cryptographic,
application, or infrastructure audit. Passing functional tests does not establish
production security. No production security support or response-time guarantee is offered.

## Trust boundaries

- Handwritten Python cryptography has not been assessed for side-channel safety.
- The built-in server defaults to `127.0.0.1`; changing its bind address does not
  add TLS or a complete authorization model. Wallet secrets reach the server.
- A chain is locally initialized and its timestamps are supplied by nodes.
  Inclusion proofs do not authenticate a person's identity or authorship.
- Demo passwords and test vectors are public by design. Generate disposable
  wallets; never reuse a cryptocurrency seed or a real password.
- Original artwork, wallet files, consent logs, and order records are private
  runtime material. Backups and custom data directories must also stay out of Git.
- IP region rules and purchase-order records are experimental; no claim is made
  that they validate actual payment settlement or determine legal eligibility.

## Reporting

Do not post live secrets, private artwork, or a working exploit affecting a live
deployment in a public issue. Use GitHub's private vulnerability reporting feature
if the repository has it enabled. Otherwise open a minimal issue requesting a
private contact channel, without exploit details or sensitive data.

Include affected version, environment, reproduction using disposable data, impact,
and a suggested fix when available. Public deployment should wait for a separate
threat model, authentication design, and security review.
